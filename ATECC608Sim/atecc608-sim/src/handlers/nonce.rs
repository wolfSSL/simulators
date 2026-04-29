/* nonce.rs
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

/// Nonce command (opcode 0x16).
///
/// P1 encodes a mode byte. The low 3 bits select the mode:
///   0x00 = Random, seed update
///   0x01 = Random, no seed update
///   0x03 = Pass-through: load the 32-byte data into the target register
/// Bits 6-7 select the target register (ATECC608A extension):
///   0x00 = TempKey         (p1 = 0x03)
///   0x40 = Message Digest Buffer    (p1 = 0x43) -- used by ECDSA sign flow
///   0x80 = Alternate Key Buffer
/// For sign/verify, both TempKey and MsgDigBuf are valid digest sources. We
/// don't bother modelling them separately -- both land in `session.tempkey`
/// and the Sign/Verify handlers accept either.
pub fn handle(session: &mut Session, cmd: &Command) -> Vec<u8> {
    let mode = cmd.p1 & 0x07;
    if mode != 0x03 {
        // Only pass-through is supported in v1.
        return atca::status_response(status::PARSE_ERROR);
    }
    if cmd.data.len() != 32 {
        return atca::status_response(status::PARSE_ERROR);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&cmd.data);
    session.tempkey.load_passthrough(&buf);
    atca::status_response(status::SUCCESS)
}
