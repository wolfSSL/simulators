/* dispatch.rs
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

use crate::frame::{build_error, build_response, parse_command, status, FrameError};
use crate::handlers;
use crate::object_store::Store;
use crate::session::Session;

/// STSAFE-A command opcodes -- values match `stsafea_cmd_code_t` in
/// services/stsafea/stsafea_commands.h (positions in the enum, since the
/// enum has no explicit numbering until EXTENDED_COMMAND_PREFIX = 0x1F).
pub mod cmd {
    pub const ECHO: u8 = 0x00;
    pub const RESET: u8 = 0x01;
    pub const GENERATE_RANDOM: u8 = 0x02;
    pub const READ: u8 = 0x05;
    pub const HIBERNATE: u8 = 0x0D;
    pub const GENERATE_KEY: u8 = 0x11;
    pub const QUERY: u8 = 0x14;
    pub const GENERATE_SIGNATURE: u8 = 0x16;
    pub const VERIFY_SIGNATURE: u8 = 0x17;
    pub const ESTABLISH_KEY: u8 = 0x18;
    pub const STANDBY: u8 = 0x19;
}

/// Parse a raw inbound frame, route to the appropriate handler, and return
/// the encoded response frame.
///
/// Frame-level errors (CRC mismatch, truncated, oversized) are reported via
/// status-code-only response frames -- never by closing the connection. Real
/// silicon does the same, and STSELib retries on those status codes.
pub fn dispatch(store: &mut Store, session: &mut Session, raw: &[u8]) -> Vec<u8> {
    let cmd = match parse_command(raw) {
        Ok(c) => c,
        Err(FrameError::BadCrc) => return build_error(status::CRC_ERROR),
        Err(FrameError::TooShort) => return build_error(status::LENGTH_ERROR),
        Err(FrameError::Overflow) => return build_error(status::LENGTH_ERROR),
    };

    if cmd.is_extended() {
        // Extended commands (start-volatile-KEK-session, generate-ECDHE,
        // hash, etc.) live behind cmd_header == 0x1F. Plain-mode wolfSSL
        // does not exercise these for STSAFE-A120 today, so reject with
        // "command not supported" -- STSELib treats this as a clean error
        // rather than a transport failure.
        return build_error(status::COMMAND_CODE_NOT_SUPPORTED);
    }

    match cmd.header {
        cmd::ECHO => handlers::echo::handle(cmd.body),
        cmd::GENERATE_RANDOM => handlers::random::handle(cmd.body),
        cmd::READ => handlers::read::handle(&store.device, cmd.body),
        cmd::GENERATE_KEY => handlers::keypair::handle(&mut store.device, cmd.body),
        cmd::GENERATE_SIGNATURE => handlers::sign::handle(&store.device, cmd.body),
        cmd::VERIFY_SIGNATURE => handlers::verify::handle(cmd.body),
        cmd::ESTABLISH_KEY => handlers::ecdh::handle(&store.device, cmd.body),
        cmd::QUERY => handlers::query::handle(&store.device, cmd.body),
        // Commands that have no observable side effect at the simulator
        // level: ack with status OK (no body).
        cmd::HIBERNATE | cmd::STANDBY | cmd::RESET => {
            session.reset();
            build_response(status::OK, &[])
        }
        _ => build_error(status::COMMAND_CODE_NOT_SUPPORTED),
    }
}
