/* info.rs
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
use crate::object_store::Device;

/// Info command, mode = Revision (P1 == 0): returns the 4-byte revision
/// word stored at config[4..8]. Real ATECC608A returns `{0x00, 0x00, 0x60, 0x02}`.
pub fn handle(device: &Device, cmd: &Command) -> Vec<u8> {
    // P1 encodes the info mode. We only support Revision (0) in v1; other
    // modes (State, GPIO, etc.) fall through to parse error.
    if cmd.p1 != 0x00 {
        return atca::status_response(status::PARSE_ERROR);
    }
    let rev: [u8; 4] = device.config[4..8].try_into().unwrap();
    atca::build_response(&rev)
}
