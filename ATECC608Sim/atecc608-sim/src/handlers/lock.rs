/* lock.rs
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
use crate::object_store::{Device, NUM_SLOTS};

/// Lock command.
///
/// P1 bit 7 clear = lock with CRC check (P2 carries a CRC of the zone we're
/// locking). Bit 7 set = lock without CRC. Bits 1-0 select the target:
///   0 = Config zone
///   1 = Data+OTP zones
///   2 = slot (slot# comes from bits 2-5 per cryptoauthlib mapping)
pub fn handle(device: &mut Device, cmd: &Command) -> Vec<u8> {
    // We intentionally skip CRC verification of the zone-to-be-locked: the
    // simulator doesn't care, and wolfSSL uses the no-CRC form anyway.
    let mode_bits = cmd.p1 & 0x03;
    match mode_bits {
        0 => {
            if device.config_locked() {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            device.set_config_locked(true);
            atca::status_response(status::SUCCESS)
        }
        1 => {
            if device.data_locked() {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            device.set_data_locked(true);
            atca::status_response(status::SUCCESS)
        }
        2 => {
            // Slot lock: slot number encoded in bits 2..5 of P1.
            let slot = ((cmd.p1 >> 2) & 0x0F) as usize;
            if slot >= NUM_SLOTS {
                return atca::status_response(status::PARSE_ERROR);
            }
            if device.slot_locked(slot) {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            device.set_slot_locked(slot, true);
            atca::status_response(status::SUCCESS)
        }
        _ => atca::status_response(status::PARSE_ERROR),
    }
}
