/* random.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STSAFEA120Sim.
 *
 * STSAFEA120Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STSAFEA120Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

use rand::rngs::OsRng;
use rand_core::RngCore;

use crate::frame::{build_error, build_response, status};

/// Generate Random command.
/// Wire: `[subject 1B] [size 1B]` -- subject is always 0x00 in plain mode,
/// size is 1..=255. Response body is `size` random bytes.
/// Service: `stsafea_generate_random` -- services/stsafea/stsafea_random.c.
pub fn handle(body: &[u8]) -> Vec<u8> {
    if body.len() != 2 {
        return build_error(status::LENGTH_ERROR);
    }
    let _subject = body[0];
    let size = body[1] as usize;
    if size == 0 {
        return build_error(status::INVALID_PARAMETER);
    }
    let mut out = vec![0u8; size];
    OsRng.fill_bytes(&mut out);
    build_response(status::OK, &out)
}
