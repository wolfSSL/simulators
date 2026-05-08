/* spi.rs
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

/// Bit-accurate SPI byte-exchange emulator for TROPIC01.
///
/// Mirrors the L1 protocol from `libtropic/src/lt_l1.c`:
///
///   Write transaction (host -> chip):
///     CSN_LOW -> SPI_SEND([REQ_ID][REQ_LEN][DATA][CRC]) -> CSN_HIGH
///   Read transaction (host <- chip), polled until ready:
///     CSN_LOW -> SPI_SEND(0xAA) returning CHIP_STATUS
///       if READY: SPI_SEND(2 dummy bytes) returning [STATUS][RSP_LEN]
///                 SPI_SEND(RSP_LEN+2 dummy) returning [DATA][CRC]
///     CSN_HIGH
///
/// Within one CSN-asserted span, the host can issue several `SPI_SEND`
/// calls, so this emulator tracks state across them. State is reset on
/// every CSN_LOW.
///
/// The first inbound MOSI byte after CSN_LOW disambiguates the transaction
/// kind: `0xAA` (`GET_RESPONSE_REQ_ID`) means "poll for a staged response",
/// any other byte begins a new request that we accumulate until the L2
/// frame is complete (REQ_ID + REQ_LEN + REQ_LEN bytes + 2 CRC bytes).
use crate::frame::{status, GET_RESPONSE_REQ_ID, MAX_L2_FRAME_SIZE};

/// `TR01_L1_CHIP_MODE_*` bits from `lt_l1.h`. The chip exposes its mode
/// as the first byte the host sees after a polled SPI_SEND; the host
/// reads `READY` before requesting the rest of the response.
pub mod chip_status {
    pub const READY: u8 = 0x01;
    pub const ALARM: u8 = 0x02;
    pub const STARTUP: u8 = 0x04;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// CSN is high; no transaction in flight.
    Idle,
    /// CSN is low and we have not yet seen any MOSI bytes; the next byte
    /// determines whether this is a write (REQ_ID != 0xAA) or a read poll.
    AwaitingFirstByte,
    /// Accumulating MOSI bytes into `request_buf` until the L2 frame is
    /// complete. We know it's complete once we have `REQ_LEN + 4` bytes.
    Writing,
    /// Servicing a polled-read transaction. Each subsequent MOSI byte the
    /// host clocks gets the next byte from `response_stream` returned as
    /// MISO. Once the host CSN_HIGH's, we drop the cursor.
    Reading,
}

/// State of the SPI line for a single host connection.
pub struct SpiEmulator {
    phase: Phase,
    /// Bytes of the in-flight L2 request being assembled (empty between
    /// transactions).
    request_buf: Vec<u8>,
    /// Whatever has been queued for the host to read next: this is
    /// `[STATUS][RSP_LEN][DATA][CRC]` -- the full L2 response frame -- and
    /// gets prefixed with CHIP_STATUS=READY at poll time.
    pending_response: Option<Vec<u8>>,
    /// Cursor into the response being clocked out. Reset to 0 on CSN_LOW.
    response_cursor: usize,
}

/// What `feed_byte` returned about the just-completed request: when the
/// caller sees `RequestComplete`, the dispatcher should be invoked on
/// `request_buf` to produce the L2 response, then `stage_response` called
/// before CSN_HIGH so the next poll can serve it.
#[derive(Debug, Clone)]
pub enum SpiOutcome {
    /// Continue clocking; this byte was buffered.
    Pending,
    /// Full L2 request received; caller should run dispatch on the bytes
    /// returned by `take_request()` and then `stage_response()`.
    RequestComplete,
}

impl Default for SpiEmulator {
    fn default() -> Self {
        Self::new()
    }
}

impl SpiEmulator {
    pub fn new() -> Self {
        Self {
            phase: Phase::Idle,
            request_buf: Vec::with_capacity(MAX_L2_FRAME_SIZE),
            pending_response: None,
            response_cursor: 0,
        }
    }

    /// Host drives CSN low. Resets per-transaction cursors but retains
    /// any staged response so the next poll can pick it up.
    pub fn csn_low(&mut self) {
        self.phase = Phase::AwaitingFirstByte;
        self.request_buf.clear();
        self.response_cursor = 0;
    }

    /// Host drives CSN high. Ends the current transaction. We keep the
    /// staged response around for the next poll cycle.
    pub fn csn_high(&mut self) {
        self.phase = Phase::Idle;
    }

    /// Process one full SPI_SEND. The host clocks `mosi.len()` bytes; we
    /// return `mosi.len()` MISO bytes plus an outcome flag. The outcome is
    /// `RequestComplete` exactly once -- on the byte that closes the L2
    /// request frame -- so the caller can run dispatch right then.
    pub fn spi_transfer(&mut self, mosi: &[u8]) -> (Vec<u8>, SpiOutcome) {
        let mut miso = Vec::with_capacity(mosi.len());
        let mut outcome = SpiOutcome::Pending;

        for &byte in mosi {
            let response_byte = self.feed_byte(byte, &mut outcome);
            miso.push(response_byte);
        }
        (miso, outcome)
    }

    fn feed_byte(&mut self, byte: u8, outcome: &mut SpiOutcome) -> u8 {
        match self.phase {
            Phase::Idle => {
                // Host sent SPI_SEND without a CSN_LOW first. Real silicon
                // would just sample garbage; return 0xFF and stay idle.
                0xFF
            }
            Phase::AwaitingFirstByte => {
                if byte == GET_RESPONSE_REQ_ID {
                    // Poll. CHIP_STATUS is always READY in this simulator
                    // -- we never enter ALARM or STARTUP mode -- so the
                    // first MISO byte is the constant `chip_status::READY`.
                    // What follows on subsequent bytes depends on whether
                    // a real L2 response is staged:
                    //   - If yes, byte stream is [STATUS][RSP_LEN][DATA][CRC]
                    //     (as built by `frame::build_response`).
                    //   - If no, byte stream is [STATUS=NO_RESP=0xFF][...zeros],
                    //     which the host's `lt_l1_read` recognises as
                    //     "still busy, retry".
                    self.phase = Phase::Reading;
                    self.response_cursor = 0;
                    if self.pending_response.is_none() {
                        // Stage a NO_RESP placeholder so the Reading-phase
                        // bytes the host clocks out have STATUS=0xFF in
                        // position 1.
                        self.pending_response = Some(vec![status::NO_RESP, 0, 0, 0]);
                    }
                    chip_status::READY
                } else {
                    // Start of a write: this is REQ_ID. We don't transition
                    // to Reading; subsequent bytes accumulate until the
                    // frame is complete.
                    self.phase = Phase::Writing;
                    self.request_buf.push(byte);
                    self.maybe_complete(outcome);
                    0x00
                }
            }
            Phase::Writing => {
                if self.request_buf.len() < MAX_L2_FRAME_SIZE {
                    self.request_buf.push(byte);
                }
                self.maybe_complete(outcome);
                0x00
            }
            Phase::Reading => {
                let resp = self
                    .pending_response
                    .as_ref()
                    .expect("pending_response must be set in Reading phase");
                let out = if self.response_cursor < resp.len() {
                    resp[self.response_cursor]
                } else {
                    // Host clocked past the response; emit 0xFF padding.
                    0xFF
                };
                self.response_cursor += 1;
                out
            }
        }
    }

    fn maybe_complete(&mut self, outcome: &mut SpiOutcome) {
        // L2 request frame layout: REQ_ID (1) + REQ_LEN (1) + DATA (REQ_LEN) + CRC (2).
        if self.request_buf.len() < 2 {
            return;
        }
        let req_len = self.request_buf[1] as usize;
        let total = 1 + 1 + req_len + 2;
        if self.request_buf.len() == total {
            *outcome = SpiOutcome::RequestComplete;
        }
    }

    /// Pull the assembled L2 request bytes out for dispatch. Resets the
    /// internal accumulator.
    pub fn take_request(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.request_buf)
    }

    /// Stage the L2 response bytes (`[STATUS][RSP_LEN][DATA][CRC]`) so
    /// they can be served on the next polled-read cycle. Calling this
    /// with `None` clears any prior staged response (so the next poll
    /// sees the synthetic NO_RESP placeholder).
    pub fn stage_response(&mut self, response: Option<Vec<u8>>) {
        self.pending_response = response;
        self.response_cursor = 0;
    }

    /// Clear the staged response after a successful read transaction.
    /// Should be called by the dispatcher after `csn_high` so the next
    /// L2 request gets a fresh slate.
    pub fn clear_response(&mut self) {
        self.pending_response = None;
        self.response_cursor = 0;
    }

    /// True if a response is currently waiting to be polled.
    pub fn has_pending_response(&self) -> bool {
        self.pending_response.is_some()
    }
}

/// Build the bytes the chip emits during a poll when it has nothing yet:
/// `[CHIP_STATUS=READY][STATUS=NO_RESP]`. lt_l1 inspects byte-1 for the
/// 0xFF sentinel and re-polls. Used by the dispatcher when a request is
/// incomplete or when we want to signal "still working" on a slow op.
#[allow(dead_code)]
pub fn build_no_resp_polling_reply() -> Vec<u8> {
    vec![chip_status::READY, status::NO_RESP, 0x00, 0x00]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{build_request, build_response};

    #[test]
    fn write_then_poll_round_trip() {
        let mut spi = SpiEmulator::new();

        // Host sends a write transaction: csn_low, send full request, csn_high.
        spi.csn_low();
        let req_bytes = build_request(0x01, &[0x00, 0x00]);
        let (_miso, outcome) = spi.spi_transfer(&req_bytes);
        assert!(matches!(outcome, SpiOutcome::RequestComplete));

        // Caller would dispatch and stage a response here; we fake one.
        let req = spi.take_request();
        assert_eq!(req, req_bytes);
        spi.stage_response(Some(build_response(status::REQUEST_OK, &[0xDE, 0xAD])));
        spi.csn_high();

        // Host now polls: csn_low, send 0xAA, expect CHIP_STATUS=READY.
        spi.csn_low();
        let (miso1, _) = spi.spi_transfer(&[GET_RESPONSE_REQ_ID]);
        assert_eq!(miso1, vec![chip_status::READY]);

        // Host clocks 2 more bytes -> expect [STATUS][RSP_LEN].
        let (miso2, _) = spi.spi_transfer(&[0x00, 0x00]);
        assert_eq!(miso2, vec![status::REQUEST_OK, 2]);

        // Host clocks 4 more bytes -> expect [DATA(2)][CRC(2)].
        let (miso3, _) = spi.spi_transfer(&[0x00; 4]);
        assert_eq!(miso3.len(), 4);
        assert_eq!(&miso3[..2], &[0xDE, 0xAD]);
        spi.csn_high();
    }

    #[test]
    fn poll_before_response_returns_ready_then_no_resp() {
        // The chip is always alive (READY bit set) but signals "no data
        // yet" via the STATUS=0xFF (NO_RESP) byte that follows.
        // This matches `lt_l1_read`'s polling loop, which only retries on
        // STATUS=NO_RESP, never on CHIP_STATUS.
        let mut spi = SpiEmulator::new();
        spi.csn_low();
        let (miso1, _) = spi.spi_transfer(&[GET_RESPONSE_REQ_ID]);
        assert_eq!(miso1, vec![chip_status::READY]);
        let (miso2, _) = spi.spi_transfer(&[0x00, 0x00]);
        assert_eq!(miso2[0], status::NO_RESP);
        spi.csn_high();
    }
}
