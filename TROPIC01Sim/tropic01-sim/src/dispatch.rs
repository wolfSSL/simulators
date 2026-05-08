/* dispatch.rs
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

/// L2 request router. Parses an L2 frame, looks at REQ_ID, and either
/// hands the body to a per-REQ handler (GET_INFO, ENCRYPTED_CMD, etc.) or
/// returns a status-only response. Handshake (M2) and Encrypted_Cmd (M3)
/// reach into `Session`; everything else just touches the `Store`.
use crate::frame::{build_response, parse_request, status, FrameError};
use crate::handlers;
use crate::object_store::Store;
use crate::session::Session;

/// L2 REQ_IDs from `lt_l2_api_structs.h`. Only the ones we route on need
/// listing; others fall through to `UNKNOWN_ERR`.
pub mod req {
    pub const GET_INFO: u8 = 0x01;
    pub const HANDSHAKE: u8 = 0x02;
    pub const ENCRYPTED_CMD: u8 = 0x04;
    pub const ENCRYPTED_SESSION_ABT: u8 = 0x08;
    pub const RESEND: u8 = 0x10;
    pub const SLEEP: u8 = 0x20;
    pub const STARTUP: u8 = 0xB3;
}

pub struct Dispatcher;

impl Dispatcher {
    /// Parse `raw`, route, and return the L2 response bytes
    /// (`[STATUS][RSP_LEN][DATA][CRC]`). The SPI emulator wraps these with
    /// the leading CHIP_STATUS byte during the polled-read transaction.
    pub fn dispatch(store: &mut Store, session: &mut Session, raw: &[u8]) -> Vec<u8> {
        let req = match parse_request(raw) {
            Ok(r) => r,
            // Frame-level errors are reported via L2 STATUS bytes -- the
            // chip never closes the link (host SDK retries on these).
            Err(FrameError::BadCrc) => return build_response(status::CRC_ERR, &[]),
            Err(FrameError::TooShort)
            | Err(FrameError::LenMismatch)
            | Err(FrameError::Overflow) => return build_response(status::GEN_ERR, &[]),
        };

        match req.req_id {
            req::GET_INFO => handlers::get_info::handle(&store.device, req.data),
            req::HANDSHAKE => match session.handshake(&store.device, req.data) {
                Ok(rsp_body) => build_response(status::REQUEST_OK, &rsp_body),
                Err(_) => {
                    session.abort();
                    build_response(status::HSK_ERR, &[])
                }
            },
            req::ENCRYPTED_CMD => {
                if !session.is_open() {
                    return build_response(status::NO_SESSION, &[]);
                }
                let plaintext = match session.unwrap_l3_request(req.data) {
                    Ok(p) => p,
                    Err(_) => {
                        // AES-GCM open failed or framing was wrong --
                        // tear down the session, mirroring real silicon.
                        session.abort();
                        return build_response(status::TAG_ERR, &[]);
                    }
                };
                let response_plaintext = handlers::l3::dispatch(&mut store.device, &plaintext);
                match session.wrap_l3_response(&response_plaintext) {
                    Ok(wire) => build_response(status::RESULT_OK, &wire),
                    Err(_) => {
                        session.abort();
                        build_response(status::GEN_ERR, &[])
                    }
                }
            }
            req::ENCRYPTED_SESSION_ABT => {
                session.abort();
                build_response(status::REQUEST_OK, &[])
            }
            req::RESEND => {
                // Real silicon would replay the prior response. We just
                // ack -- nothing in libtropic's main flow exercises this.
                build_response(status::REQUEST_OK, &[])
            }
            req::SLEEP => {
                session.abort();
                build_response(status::REQUEST_OK, &[])
            }
            req::STARTUP => {
                session.abort();
                build_response(status::REQUEST_OK, &[])
            }
            _ => build_response(status::UNKNOWN_ERR, &[]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::build_request;

    #[test]
    fn unknown_req_id_returns_unknown_err() {
        let mut store = Store::fresh();
        let mut session = Session::new();
        let raw = build_request(0x77, &[]);
        let resp = Dispatcher::dispatch(&mut store, &mut session, &raw);
        assert_eq!(resp[0], status::UNKNOWN_ERR);
    }

    #[test]
    fn bad_crc_returns_crc_err() {
        let mut store = Store::fresh();
        let mut session = Session::new();
        let mut raw = build_request(req::GET_INFO, &[0x01, 0]);
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        let resp = Dispatcher::dispatch(&mut store, &mut session, &raw);
        assert_eq!(resp[0], status::CRC_ERR);
    }

    #[test]
    fn get_info_chip_id_round_trip() {
        let mut store = Store::fresh();
        let mut session = Session::new();
        let raw = build_request(req::GET_INFO, &[0x01, 0]);
        let resp = Dispatcher::dispatch(&mut store, &mut session, &raw);
        assert_eq!(resp[0], status::REQUEST_OK);
        // [STATUS][RSP_LEN=128][CHIP_ID(12) + zeros][CRC]
        assert_eq!(resp[1], 128);
        assert_eq!(&resp[2..2 + 12], &store.device.chip_id);
    }

    #[test]
    fn encrypted_cmd_without_session_is_no_session() {
        let mut store = Store::fresh();
        let mut session = Session::new();
        let raw = build_request(req::ENCRYPTED_CMD, &[0; 16]);
        let resp = Dispatcher::dispatch(&mut store, &mut session, &raw);
        assert_eq!(resp[0], status::NO_SESSION);
    }
}
