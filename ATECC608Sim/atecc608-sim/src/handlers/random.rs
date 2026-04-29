/* random.rs
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

use crate::atca::{self, Command};
use crate::object_store::Device;
use rand::RngCore;

/// Random command: returns 32 cryptographically random bytes regardless of
/// the Mode/UpdateSeed flags. Real silicon has knobs to skip seed update;
/// we don't model those because wolfSSL doesn't care.
pub fn handle(_device: &Device, _cmd: &Command) -> Vec<u8> {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    atca::build_response(&buf)
}
