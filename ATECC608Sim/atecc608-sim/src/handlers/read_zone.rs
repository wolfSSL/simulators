/* read_zone.rs
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

/// Read command.
///
/// P1 bit 7 set = 32-byte read, clear = 4-byte read.
/// P1 bits 0-1 = zone (0=config, 1=OTP, 2=data).
/// P2 (little-endian u16) = address. For config/OTP, the address uses the
/// datasheet block/offset encoding: bits 4-3 select the 32-byte block and
/// bits 2-0 select the 4-byte word within that block. For 32-byte reads,
/// the word offset is ignored and the whole block is returned.
/// For data zone: address encodes (slot, block, offset).
pub fn handle(device: &Device, cmd: &Command) -> Vec<u8> {
    let is_32 = cmd.p1 & 0x80 != 0;
    let zone_id = cmd.p1 & 0x03;
    let addr = cmd.p2;
    let len = if is_32 { 32 } else { 4 };

    match zone_id {
        zone::CONFIG => read_linear(&device.config, CONFIG_SIZE, addr, len),
        zone::OTP => read_linear(&device.otp, OTP_SIZE, addr, len),
        zone::DATA => read_data(device, addr, len),
        _ => atca::status_response(status::PARSE_ERROR),
    }
}

fn read_linear(zone: &[u8], size: usize, addr: u16, len: usize) -> Vec<u8> {
    // ATCA address encoding for config/OTP: byte_offset = (block << 3) + offset*4 where
    // offset is bits 2-0 of addr and block is bits 4-3. For word reads, offset is used
    // directly; for 32-byte reads, offset is ignored. We decode both cases.
    let offset = (addr & 0x7) as usize;
    let block = ((addr >> 3) & 0x3) as usize;
    let byte_offset = block * 32 + if len == 32 { 0 } else { offset * 4 };
    if byte_offset + len > size {
        return atca::status_response(status::PARSE_ERROR);
    }
    atca::build_response(&zone[byte_offset..byte_offset + len])
}

fn read_data(device: &Device, addr: u16, len: usize) -> Vec<u8> {
    // For data zone: bits 0-2 = offset-in-block (words), bits 3-7 = block,
    // bits 8-11 = slot.
    let offset = (addr & 0x7) as usize;
    let block = ((addr >> 3) & 0x1F) as usize;
    let slot = ((addr >> 8) & 0x0F) as usize;
    if slot >= NUM_SLOTS {
        return atca::status_response(status::PARSE_ERROR);
    }
    let byte_offset = block * 32 + if len == 32 { 0 } else { offset * 4 };
    if byte_offset + len > SLOT_SIZE {
        return atca::status_response(status::PARSE_ERROR);
    }
    let slot_data = &device.slots[slot].data;
    // Zero-pad if the slot has not been written yet. Real silicon's
    // behavior here depends on IsSecret/EncRead/ReadKey; in our permissive
    // default config, unwritten bytes read as zero.
    let mut out = vec![0u8; len];
    let avail = slot_data.len().min(byte_offset + len);
    if avail > byte_offset {
        out[..avail - byte_offset].copy_from_slice(&slot_data[byte_offset..avail]);
    }
    atca::build_response(&out)
}
