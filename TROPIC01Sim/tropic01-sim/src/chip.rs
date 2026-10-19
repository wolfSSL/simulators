/* chip.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of TROPIC01Sim.
 *
 * TROPIC01Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * TROPIC01Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

//! The chip as seen from the SPI bus: L1 byte exchange and the L2 frame
//! layer.
//!
//! L1 (matches the bench chip's MISO traces):
//!
//! * Every transaction's first MISO byte is CHIP_STATUS: READY (0x01) in
//!   Application mode, READY|STARTUP (0x05) in Maintenance mode, ALARM
//!   (0x02) in Alarm mode (0x03 on the transaction that raised it).
//! * Request transactions (first MOSI byte != 0xAA) return 0xFF after
//!   CHIP_STATUS.
//! * A GET_RESP poll (first MOSI byte 0xAA) answers CHIP_STATUS=0x00 (not
//!   ready) for `busy_polls` polls after each request, then READY followed
//!   by the next queued L2 response frame, or READY followed by 0xFF
//!   (STATUS=NO_RESP) when nothing is queued. A frame is consumed once it
//!   has been clocked out completely; it then becomes the frame that a
//!   Resend_Req replays. The replay goes in front of the frames not fetched
//!   yet, so a host that re-reads one chunk of a long result still gets the
//!   rest.
//!
//! L2 requests are validated like the firmware does: a wrong REQ_LEN or
//! parameter is GEN_ERR, an unknown REQ_ID is UNKNOWN_ERR. L3 packets
//! larger than one 252-byte chunk are reassembled from Encrypted_Cmd_Req
//! chunks (REQUEST_CONT until complete, then REQUEST_OK) and results are
//! split into RESULT_CONT / RESULT_OK chunks.
//!
//! Like Tropic Square's model, the firmware reads the effective
//! configuration (R-Config AND I-Config) once after a power cycle or a
//! Startup_Req reboot and uses that snapshot until the next one;
//! configuration writes are stored at once but take effect only then.

use std::collections::VecDeque;

use crate::frame::{
    build_response, parse_request, status, FrameError, GET_RESPONSE_REQ_ID, MAX_L2_DATA_SIZE,
    MAX_L2_FRAME_SIZE,
};
use crate::handlers;
use crate::handlers::l3::L3Outcome;
use crate::object_store::{Device, Store};
use crate::personality::Personality;
use crate::session::Session;

/// `TR01_L1_CHIP_MODE_*` bits.
pub mod chip_status {
    pub const READY: u8 = 0x01;
    pub const ALARM: u8 = 0x02;
    pub const STARTUP: u8 = 0x04;
}

/// L2 REQ_IDs (`lt_l2_api_structs.h`).
pub mod req {
    pub const GET_INFO: u8 = 0x01;
    pub const HANDSHAKE: u8 = 0x02;
    pub const ENCRYPTED_CMD: u8 = 0x04;
    pub const ENCRYPTED_SESSION_ABT: u8 = 0x08;
    pub const RESEND: u8 = 0x10;
    pub const SLEEP: u8 = 0x20;
    pub const GET_LOG: u8 = 0xa2;
    pub const STARTUP: u8 = 0xb3;
}

pub const SLEEP_KIND_SLEEP: u8 = 0x05;
pub const STARTUP_REBOOT: u8 = 0x01;
pub const STARTUP_MAINTENANCE_REBOOT: u8 = 0x03;

/// L3 packet framing overhead: `[size u16][ciphertext][tag 16B]`.
const L3_SIZE_LEN: usize = 2;
const L3_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Application,
    Maintenance,
    Alarm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    First,
    Request,
    Response,
    NoResponse,
}

pub struct Chip {
    personality: Personality,
    mode: Mode,
    /// Report CHIP_STATUS 0x03 once when Alarm mode was just entered.
    alarm_fresh: bool,
    session: Session,
    phase: Phase,
    request: Vec<u8>,
    queue: VecDeque<Vec<u8>>,
    cursor: usize,
    last_response: Option<Vec<u8>>,
    busy_polls: u32,
    busy_left: u32,
    /// Encrypted_Cmd_Req chunk reassembly buffer and expected packet size.
    l3_packet: Vec<u8>,
    l3_expected: usize,
    /// Effective configuration read at start-up; None until first needed
    /// after a power cycle or reboot.
    active_config: Option<Vec<u32>>,
    /// An executed command may have changed the persistent store.
    store_dirty: bool,
}

impl Chip {
    pub fn new(personality: Personality) -> Self {
        Self {
            personality,
            mode: Mode::Application,
            alarm_fresh: false,
            session: Session::new(),
            phase: Phase::Idle,
            request: Vec::with_capacity(MAX_L2_FRAME_SIZE),
            queue: VecDeque::new(),
            cursor: 0,
            last_response: None,
            busy_polls: 1,
            busy_left: 0,
            l3_packet: Vec::new(),
            l3_expected: 0,
            active_config: None,
            store_dirty: false,
        }
    }

    /// Number of polls answered "not ready" after each request. The bench
    /// chip needs one for GET_INFO; zero makes every response immediate.
    pub fn set_busy_polls(&mut self, n: u32) {
        self.busy_polls = n;
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    /// True (once) when a command executed since the last call may have
    /// changed the persistent store, so the caller knows when to save it.
    pub fn take_store_dirty(&mut self) -> bool {
        std::mem::take(&mut self.store_dirty)
    }

    /// The effective configuration in force, read from the store the first
    /// time it is needed after a power cycle or reboot.
    fn active_config(&mut self, dev: &Device) -> &[u32] {
        self.active_config
            .get_or_insert_with(|| dev.effective_config())
    }

    /// Power cycle: volatile state is lost, the chip boots into Application
    /// mode (which also clears Alarm mode).
    pub fn power_cycle(&mut self) {
        let busy = self.busy_polls;
        *self = Chip::new(self.personality);
        self.busy_polls = busy;
    }

    fn chip_status(&mut self) -> u8 {
        match self.mode {
            Mode::Application => chip_status::READY,
            Mode::Maintenance => chip_status::READY | chip_status::STARTUP,
            Mode::Alarm => {
                if self.alarm_fresh {
                    self.alarm_fresh = false;
                    chip_status::READY | chip_status::ALARM
                } else {
                    chip_status::ALARM
                }
            }
        }
    }

    pub fn csn_low(&mut self) {
        self.phase = Phase::First;
        self.request.clear();
        self.cursor = 0;
    }

    pub fn csn_high(&mut self) {
        if self.phase == Phase::Response {
            if let Some(front) = self.queue.front() {
                if self.cursor >= front.len() {
                    self.last_response = self.queue.pop_front();
                }
            }
        }
        self.cursor = 0;
        self.phase = Phase::Idle;
    }

    /// Clock `mosi` through the chip and return the MISO bytes. A request
    /// frame is executed as soon as its last byte arrives.
    pub fn transfer(&mut self, store: &mut Store, mosi: &[u8]) -> Vec<u8> {
        let mut miso = Vec::with_capacity(mosi.len());
        for &b in mosi {
            let out = match self.phase {
                Phase::Idle => 0xff,
                Phase::First => self.first_byte(store, b),
                Phase::Request => {
                    self.push_request_byte(store, b);
                    0xff
                }
                Phase::Response => {
                    let out = self
                        .queue
                        .front()
                        .and_then(|f| f.get(self.cursor).copied())
                        .unwrap_or(0xff);
                    self.cursor += 1;
                    out
                }
                Phase::NoResponse => status::NO_RESP,
            };
            miso.push(out);
        }
        miso
    }

    fn first_byte(&mut self, store: &mut Store, b: u8) -> u8 {
        let cs = self.chip_status();
        if b == GET_RESPONSE_REQ_ID {
            if self.mode == Mode::Alarm {
                self.phase = Phase::NoResponse;
            } else if !self.queue.is_empty() && self.busy_left > 0 {
                // Busy: READY clear, mode bits kept (0x00 in Application,
                // 0x04 in Maintenance mode on the bench chip).
                self.busy_left -= 1;
                self.phase = Phase::NoResponse;
                return cs & !chip_status::READY;
            } else if self.queue.is_empty() {
                self.phase = Phase::NoResponse;
            } else {
                self.phase = Phase::Response;
                self.cursor = 0;
            }
            cs
        } else {
            self.phase = Phase::Request;
            self.push_request_byte(store, b);
            cs
        }
    }

    fn push_request_byte(&mut self, store: &mut Store, b: u8) {
        if self.request.len() < MAX_L2_FRAME_SIZE {
            self.request.push(b);
        }
        if self.request.len() >= 2 && self.request.len() == self.request[1] as usize + 4 {
            let raw = std::mem::take(&mut self.request);
            self.execute(store, &raw);
            // Ignore anything clocked after the frame in this transaction.
            self.phase = Phase::NoResponse;
        }
    }

    fn execute(&mut self, store: &mut Store, raw: &[u8]) {
        if self.mode == Mode::Alarm {
            return;
        }
        // Resend_Req replays the last response frame verbatim, in front of
        // the frames the host has not fetched yet (libtropic re-reads a
        // frame whose CRC failed and then carries on with the rest).
        let resend =
            matches!(parse_request(raw), Ok(r) if r.req_id == req::RESEND && r.data.is_empty());
        if resend {
            if let Some(f) = self.last_response.clone() {
                self.queue.push_front(f);
                self.busy_left = self.busy_polls;
                return;
            }
        }
        let frames = self.process(store, raw);
        // Any other request discards responses the host never fetched.
        self.queue = frames.into();
        self.busy_left = if self.queue.is_empty() {
            0
        } else {
            self.busy_polls
        };
    }

    /// Execute one L2 request and return the response frames to queue.
    fn process(&mut self, store: &mut Store, raw: &[u8]) -> Vec<Vec<u8>> {
        let req = match parse_request(raw) {
            Ok(r) => r,
            Err(FrameError::BadCrc) => return vec![build_response(status::CRC_ERR, &[])],
            Err(_) => return vec![build_response(status::GEN_ERR, &[])],
        };
        let data = req.data;

        // A Resend_Req that execute() could not replay: it carries data, or
        // no response has been sent yet.
        if req.req_id == req::RESEND {
            return vec![build_response(status::GEN_ERR, &[])];
        }

        match (self.mode, req.req_id) {
            (_, req::GET_INFO) => {
                if data.len() != 2 {
                    return vec![gen_err()];
                }
                vec![handlers::get_info::handle(
                    &store.device,
                    self.mode == Mode::Maintenance,
                    data[0],
                    data[1],
                )]
            }
            (_, req::GET_LOG) => {
                if !data.is_empty() {
                    return vec![gen_err()];
                }
                vec![build_response(
                    status::REQUEST_OK,
                    &self.personality.fw_log(),
                )]
            }
            (_, req::STARTUP) => {
                if data.len() != 1 {
                    return vec![gen_err()];
                }
                match data[0] {
                    STARTUP_REBOOT => {
                        self.reboot(Mode::Application);
                        vec![build_response(status::REQUEST_OK, &[])]
                    }
                    STARTUP_MAINTENANCE_REBOOT => {
                        // CFG_START_UP.MAINTENANCE_ENA (bit 3) gates the
                        // maintenance restart.
                        let ena = self.active_config(&store.device)[0x000 / 4] & (1 << 3) != 0;
                        self.reboot(if ena {
                            Mode::Maintenance
                        } else {
                            Mode::Application
                        });
                        vec![build_response(status::REQUEST_OK, &[])]
                    }
                    _ => vec![gen_err()],
                }
            }
            (Mode::Application, req::HANDSHAKE) => self.handshake(store, data),
            (Mode::Application, req::ENCRYPTED_CMD) => self.encrypted_cmd(store, data),
            (Mode::Application, req::ENCRYPTED_SESSION_ABT) => {
                if !data.is_empty() {
                    return vec![gen_err()];
                }
                self.drop_session();
                vec![build_response(status::REQUEST_OK, &[])]
            }
            (Mode::Application, req::SLEEP) => {
                if data.len() != 1 || data[0] != SLEEP_KIND_SLEEP {
                    return vec![gen_err()];
                }
                // CFG_SLEEP_MODE.SLEEP_MODE_EN (bit 0)
                if self.active_config(&store.device)[0x018 / 4] & 1 == 0 {
                    return vec![build_response(status::RESP_DISABLED, &[])];
                }
                self.drop_session();
                vec![build_response(status::REQUEST_OK, &[])]
            }
            _ => vec![build_response(status::UNKNOWN_ERR, &[])],
        }
    }

    fn reboot(&mut self, mode: Mode) {
        self.drop_session();
        self.mode = mode;
        // The firmware reads the configuration again when it starts
        self.active_config = None;
    }

    fn drop_session(&mut self) {
        self.session.abort();
        self.l3_packet.clear();
        self.l3_expected = 0;
    }

    fn handshake(&mut self, store: &mut Store, data: &[u8]) -> Vec<Vec<u8>> {
        if data.len() != crate::session::HANDSHAKE_REQ_LEN {
            return vec![gen_err()];
        }
        if data[32] > 3 && self.personality.bad_pairing_index_alarms() {
            self.drop_session();
            self.mode = Mode::Alarm;
            self.alarm_fresh = true;
            return Vec::new();
        }
        self.l3_packet.clear();
        self.l3_expected = 0;
        match self.session.handshake(&store.device, data) {
            Ok(body) => vec![build_response(status::REQUEST_OK, &body)],
            Err(_) => {
                self.session.abort();
                vec![build_response(status::HSK_ERR, &[])]
            }
        }
    }

    fn encrypted_cmd(&mut self, store: &mut Store, chunk: &[u8]) -> Vec<Vec<u8>> {
        if !self.session.is_open() {
            self.l3_packet.clear();
            self.l3_expected = 0;
            return vec![build_response(status::NO_SESSION, &[])];
        }
        if self.l3_packet.is_empty() {
            if chunk.len() < L3_SIZE_LEN {
                return vec![gen_err()];
            }
            let size = u16::from_le_bytes([chunk[0], chunk[1]]) as usize;
            self.l3_expected = L3_SIZE_LEN + size + L3_TAG_LEN;
        }
        self.l3_packet.extend_from_slice(chunk);
        if self.l3_packet.len() < self.l3_expected {
            return vec![build_response(status::REQUEST_CONT, &[])];
        }
        let packet = std::mem::take(&mut self.l3_packet);
        let complete = packet.len() == self.l3_expected;
        self.l3_expected = 0;
        let ack = build_response(status::REQUEST_OK, &[]);
        if !complete {
            self.drop_session();
            return vec![ack, gen_err()];
        }

        let plaintext = match self.session.unwrap_l3_request(&packet) {
            Ok(p) => p,
            Err(_) => {
                self.drop_session();
                return vec![ack, build_response(status::TAG_ERR, &[])];
            }
        };
        let pkey_index = self
            .session
            .keys
            .as_ref()
            .map(|k| k.pkey_index)
            .unwrap_or(0);
        if self.active_config.is_none() {
            self.active_config = Some(store.device.effective_config());
        }
        let cfg = self.active_config.as_deref().unwrap_or(&[]);
        let outcome = handlers::l3::dispatch(
            &mut store.device,
            cfg,
            self.personality,
            pkey_index,
            &plaintext,
        );
        if plaintext
            .first()
            .is_some_and(|&id| handlers::l3::mutates_store(id))
        {
            self.store_dirty = true;
        }
        let result = match outcome {
            L3Outcome::Result(r) => r,
            L3Outcome::GenErr => {
                self.drop_session();
                return vec![ack, gen_err()];
            }
        };
        let wire = match self.session.wrap_l3_response(&result) {
            Ok(w) => w,
            Err(_) => {
                self.drop_session();
                return vec![ack, gen_err()];
            }
        };
        let mut frames = vec![ack];
        let chunks: Vec<&[u8]> = wire.chunks(MAX_L2_DATA_SIZE).collect();
        for (i, c) in chunks.iter().enumerate() {
            let st = if i + 1 == chunks.len() {
                status::RESULT_OK
            } else {
                status::RESULT_CONT
            };
            frames.push(build_response(st, c));
        }
        frames
    }
}

fn gen_err() -> Vec<u8> {
    build_response(status::GEN_ERR, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::build_request;

    /// Host side of one L2 exchange: write the request, poll until READY,
    /// read the frame. Returns (chip_status_of_last_poll, frame).
    fn exchange(chip: &mut Chip, store: &mut Store, req_frame: &[u8]) -> (u8, Vec<u8>) {
        chip.csn_low();
        let miso = chip.transfer(store, req_frame);
        chip.csn_high();
        assert_eq!(miso[1..].iter().all(|&b| b == 0xff), true);
        read_frame(chip, store)
    }

    fn read_frame(chip: &mut Chip, store: &mut Store) -> (u8, Vec<u8>) {
        for _ in 0..10 {
            chip.csn_low();
            let cs = chip.transfer(store, &[GET_RESPONSE_REQ_ID])[0];
            if cs & chip_status::READY == 0 {
                chip.csn_high();
                continue;
            }
            let hdr = chip.transfer(store, &[0, 0]);
            if hdr[0] == status::NO_RESP {
                chip.csn_high();
                return (cs, hdr);
            }
            let mut frame = hdr.clone();
            frame.extend(chip.transfer(store, &vec![0; hdr[1] as usize + 2]));
            chip.csn_high();
            return (cs, frame);
        }
        panic!("chip never became ready");
    }

    #[test]
    fn get_info_round_trip_with_busy_poll() {
        let mut store = Store::fresh();
        let mut chip = Chip::new(Personality::Es012);
        let (cs, f) = exchange(
            &mut chip,
            &mut store,
            &build_request(req::GET_INFO, &[0x02, 0]),
        );
        assert_eq!(cs, chip_status::READY);
        assert_eq!(f[0], status::REQUEST_OK);
        assert_eq!(&f[2..6], &Personality::Es012.riscv_fw_version());
        // Consumed: the next poll has nothing.
        let (_, f2) = read_frame(&mut chip, &mut store);
        assert_eq!(f2[0], status::NO_RESP);
    }

    #[test]
    fn resend_replays_last_frame_including_errors() {
        let mut store = Store::fresh();
        let mut chip = Chip::new(Personality::Es012);
        let mut bad = build_request(req::GET_INFO, &[0x01, 0]);
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        let (_, f) = exchange(&mut chip, &mut store, &bad);
        assert_eq!(f[0], status::CRC_ERR);
        let (_, f2) = exchange(&mut chip, &mut store, &build_request(req::RESEND, &[]));
        assert_eq!(f2, f);
    }

    #[test]
    fn l2_validation_matches_hardware() {
        let mut store = Store::fresh();
        let mut chip = Chip::new(Personality::Es012);
        let cases: &[(u8, &[u8], u8)] = &[
            (req::GET_INFO, &[0x03, 0], status::GEN_ERR),
            (req::GET_INFO, &[0x00, 30], status::GEN_ERR),
            (req::GET_INFO, &[0x00, 29], status::REQUEST_OK),
            (req::GET_INFO, &[0xb0, 1], status::GEN_ERR),
            (req::GET_INFO, &[0x01], status::GEN_ERR),
            (0x77, &[], status::UNKNOWN_ERR),
            (req::ENCRYPTED_SESSION_ABT, &[0], status::GEN_ERR),
            (req::ENCRYPTED_SESSION_ABT, &[], status::REQUEST_OK),
            (req::SLEEP, &[0], status::GEN_ERR),
            (req::SLEEP, &[SLEEP_KIND_SLEEP], status::REQUEST_OK),
            (req::STARTUP, &[0x02], status::GEN_ERR),
            (req::HANDSHAKE, &[0; 32], status::GEN_ERR),
            (req::ENCRYPTED_CMD, &[1, 0, 0], status::NO_SESSION),
        ];
        for (id, data, want) in cases {
            let (_, f) = exchange(&mut chip, &mut store, &build_request(*id, data));
            assert_eq!(f[0], *want, "req {id:#04x} {data:02x?}");
        }
    }

    #[test]
    fn bad_pairing_index_raises_alarm_until_power_cycle() {
        let mut store = Store::fresh();
        let mut chip = Chip::new(Personality::Es012);
        let mut hs = vec![0x42u8; 33];
        hs[32] = 4;
        chip.csn_low();
        chip.transfer(&mut store, &build_request(req::HANDSHAKE, &hs));
        chip.csn_high();
        chip.csn_low();
        assert_eq!(chip.transfer(&mut store, &[GET_RESPONSE_REQ_ID])[0], 0x03);
        chip.csn_high();
        chip.csn_low();
        assert_eq!(chip.transfer(&mut store, &[GET_RESPONSE_REQ_ID])[0], 0x02);
        chip.csn_high();
        chip.power_cycle();
        assert_eq!(chip.mode(), Mode::Application);

        let mut prod = Chip::new(Personality::Fw220);
        let (_, f) = exchange(&mut prod, &mut store, &build_request(req::HANDSHAKE, &hs));
        assert_eq!(f[0], status::HSK_ERR);
    }

    #[test]
    fn maintenance_mode_reports_bootloader() {
        let mut store = Store::fresh();
        let mut chip = Chip::new(Personality::Es012);
        let (_, f) = exchange(
            &mut chip,
            &mut store,
            &build_request(req::STARTUP, &[STARTUP_MAINTENANCE_REBOOT]),
        );
        assert_eq!(f[0], status::REQUEST_OK);
        let (cs, f) = exchange(
            &mut chip,
            &mut store,
            &build_request(req::GET_INFO, &[0x02, 0]),
        );
        assert_eq!(cs, chip_status::READY | chip_status::STARTUP);
        assert_eq!(&f[2..6], &Personality::Es012.bootloader_version());
        let (_, f) = exchange(
            &mut chip,
            &mut store,
            &build_request(req::ENCRYPTED_CMD, &[0; 4]),
        );
        assert_eq!(f[0], status::UNKNOWN_ERR);
        let (_, f) = exchange(
            &mut chip,
            &mut store,
            &build_request(req::STARTUP, &[STARTUP_REBOOT]),
        );
        assert_eq!(f[0], status::REQUEST_OK);
        assert_eq!(chip.mode(), Mode::Application);
    }
}
