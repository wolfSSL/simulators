/* sha.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of ATECC608Sim.
 *
 * ATECC608Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * ATECC608Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

use crate::atca::{self, status, Command};
use crate::session::Session;
use sha2::{Digest, Sha256};

/// SHA command (opcode 0x47).
///
/// P1 mode:
///   0x00 = Start    (begin a new SHA-256 context)
///   0x01 = Update   (absorb 64 bytes of data into the running context)
///   0x02 = End      (finalize, optionally absorbing trailing 0..63 bytes)
///   0x03 = Public   (single-call: hash exactly the input and return)
///
/// The ATECC608 adds a few extended modes (HMAC_START, KEY-selected HMAC,
/// etc.). wolfSSL doesn't use those for its SHA path so we treat any unknown
/// mode as a parse error.
pub fn handle(session: &mut Session, cmd: &Command) -> Vec<u8> {
    match cmd.p1 {
        0x00 => {
            session.sha.start();
            atca::status_response(status::SUCCESS)
        }
        0x01 => {
            if !session.sha.update(&cmd.data) {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            atca::status_response(status::SUCCESS)
        }
        0x02 => {
            let digest = match session.sha.finish(&cmd.data) {
                Some(d) => d,
                None => return atca::status_response(status::EXECUTION_ERROR),
            };
            atca::build_response(&digest)
        }
        0x03 => {
            let digest: [u8; 32] = Sha256::digest(&cmd.data).into();
            atca::build_response(&digest)
        }
        _ => atca::status_response(status::PARSE_ERROR),
    }
}
