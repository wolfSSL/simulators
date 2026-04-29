/* write_zone.rs
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
use crate::object_store::{zone, Device, CONFIG_SIZE, NUM_SLOTS, OTP_SIZE, SLOT_SIZE};

/// Write command.
///
/// P1 encodes zone + 32-byte mode (bit 7). Low bits: 0=config, 1=OTP, 2=data.
/// Bit 6 indicates the data is encrypted (we reject encrypted writes in v1).
/// Data payload is either 4 or 32 bytes.
pub fn handle(device: &mut Device, cmd: &Command) -> Vec<u8> {
    if cmd.p1 & 0x40 != 0 {
        // Encrypted write — requires a GenDig-derived key we don't simulate.
        return atca::status_response(status::EXECUTION_ERROR);
    }
    let is_32 = cmd.p1 & 0x80 != 0;
    let zone_id = cmd.p1 & 0x03;
    let expected = if is_32 { 32 } else { 4 };
    if cmd.data.len() != expected {
        return atca::status_response(status::PARSE_ERROR);
    }

    let result = match zone_id {
        zone::CONFIG => write_config(device, cmd.p2, &cmd.data),
        zone::OTP => write_otp(device, cmd.p2, &cmd.data),
        zone::DATA => write_data(device, cmd.p2, &cmd.data),
        _ => return atca::status_response(status::PARSE_ERROR),
    };

    match result {
        Ok(()) => atca::status_response(status::SUCCESS),
        Err(sw) => atca::status_response(sw),
    }
}

fn addr_to_byte_offset(addr: u16, len: usize) -> usize {
    let offset = (addr & 0x7) as usize;
    let block = ((addr >> 3) & 0x3) as usize;
    block * 32 + if len == 32 { 0 } else { offset * 4 }
}

fn write_config(device: &mut Device, addr: u16, data: &[u8]) -> Result<(), u8> {
    // Once the config zone is locked only a narrow set of bytes remain
    // writable (SlotLocked at 88..90, UseFlag/UpdateCount, ChipMode bits).
    // wolfSSL never writes config post-lock, so a flat refuse is fine.
    if device.config_locked() {
        return Err(status::EXECUTION_ERROR);
    }
    let off = addr_to_byte_offset(addr, data.len());
    if off + data.len() > CONFIG_SIZE {
        return Err(status::PARSE_ERROR);
    }
    device.config[off..off + data.len()].copy_from_slice(data);
    Ok(())
}

fn write_otp(device: &mut Device, addr: u16, data: &[u8]) -> Result<(), u8> {
    if device.data_locked() {
        // OTP locks jointly with Data per LockValue byte.
        return Err(status::EXECUTION_ERROR);
    }
    let off = addr_to_byte_offset(addr, data.len());
    if off + data.len() > OTP_SIZE {
        return Err(status::PARSE_ERROR);
    }
    device.otp[off..off + data.len()].copy_from_slice(data);
    Ok(())
}

fn write_data(device: &mut Device, addr: u16, data: &[u8]) -> Result<(), u8> {
    let offset = (addr & 0x7) as usize;
    let block = ((addr >> 3) & 0x1F) as usize;
    let slot = ((addr >> 8) & 0x0F) as usize;
    if slot >= NUM_SLOTS {
        return Err(status::PARSE_ERROR);
    }
    // Per-slot lock overrides the global data-lock: if the slot is
    // individually unlocked via SlotLocked word, writes succeed even after
    // Data zone lock. This is the path wolfSSL relies on for GenKey-able slots.
    if device.data_locked() && device.slot_locked(slot) {
        return Err(status::EXECUTION_ERROR);
    }
    let off = block * 32 + if data.len() == 32 { 0 } else { offset * 4 };
    if off + data.len() > SLOT_SIZE {
        return Err(status::PARSE_ERROR);
    }
    let slot_data = &mut device.slots[slot].data;
    if slot_data.len() < off + data.len() {
        slot_data.resize(off + data.len(), 0);
    }
    slot_data[off..off + data.len()].copy_from_slice(data);
    Ok(())
}
