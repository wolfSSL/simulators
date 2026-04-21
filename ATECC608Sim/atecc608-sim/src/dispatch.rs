/* dispatch.rs
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

/// Central opcode dispatch. `raw_packet` is the packet as it arrives after
/// the 0x03 word-address byte (i.e. starts with the count byte). The returned
/// bytes are the full response frame to send back on the wire.
use crate::atca::{self, status, Command};
use crate::handlers;
use crate::object_store::Device;
use crate::session::Session;

/// Opcode table. Keep in one place so dispatch and tests agree.
pub mod opcode {
    pub const READ: u8 = 0x02;
    pub const WRITE: u8 = 0x12;
    pub const LOCK: u8 = 0x17;
    pub const NONCE: u8 = 0x16;
    pub const RANDOM: u8 = 0x1B;
    pub const INFO: u8 = 0x30;
    pub const GENKEY: u8 = 0x40;
    pub const SIGN: u8 = 0x41;
    pub const ECDH: u8 = 0x43;
    pub const VERIFY: u8 = 0x45;
    pub const SHA: u8 = 0x47;
}

pub fn dispatch(device: &mut Device, session: &mut Session, raw_packet: &[u8]) -> Vec<u8> {
    let cmd = match Command::parse(raw_packet) {
        Ok(c) => c,
        Err(sw) => return atca::status_response(sw),
    };

    match cmd.opcode {
        opcode::INFO => handlers::info::handle(device, &cmd),
        opcode::RANDOM => handlers::random::handle(device, &cmd),
        opcode::READ => handlers::read_zone::handle(device, &cmd),
        opcode::WRITE => handlers::write_zone::handle(device, &cmd),
        opcode::LOCK => handlers::lock::handle(device, &cmd),
        opcode::SHA => handlers::sha::handle(session, &cmd),
        opcode::NONCE => handlers::nonce::handle(session, &cmd),
        opcode::GENKEY => handlers::genkey::handle(device, session, &cmd),
        opcode::SIGN => handlers::sign::handle(device, session, &cmd),
        opcode::VERIFY => handlers::verify::handle(device, session, &cmd),
        opcode::ECDH => handlers::ecdh::handle(device, session, &cmd),
        _ => atca::status_response(status::PARSE_ERROR),
    }
}
