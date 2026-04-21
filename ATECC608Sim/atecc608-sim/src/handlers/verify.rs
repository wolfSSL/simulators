/* verify.rs
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
use crate::session::Session;
use p256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    EncodedPoint,
};

/// Verify command (opcode 0x45).
///
/// P1 mode (low 3 bits):
///   0x02 = External — caller supplies 64-byte pubkey + 64-byte signature
///          inline. The message to verify is taken from TempKey or
///          MsgDigBuf (both share a scratch register in our model).
/// Higher bits on ATECC608A select SOURCE_MSGDIGBUF / IncludeSlots similar
/// to Sign. We ignore them and use whatever digest Nonce last loaded.
/// Data = signature(64) || pubkey(64 X||Y)
/// Response = 1 byte status. SUCCESS on valid, MISCOMPARE on invalid.
pub fn handle(_device: &Device, session: &mut Session, cmd: &Command) -> Vec<u8> {
    if cmd.p1 & 0x07 != 0x02 {
        return atca::status_response(status::EXECUTION_ERROR);
    }
    if cmd.data.len() != 128 {
        return atca::status_response(status::PARSE_ERROR);
    }
    if !session.tempkey.valid {
        return atca::status_response(status::EXECUTION_ERROR);
    }

    let sig_bytes = &cmd.data[..64];
    let pk_bytes = &cmd.data[64..128];

    let sig = match Signature::try_from(sig_bytes) {
        Ok(s) => s,
        Err(_) => return atca::status_response(status::PARSE_ERROR),
    };
    let point = EncodedPoint::from_untagged_bytes(pk_bytes.into());
    let vk = match VerifyingKey::from_encoded_point(&point) {
        Ok(k) => k,
        Err(_) => return atca::status_response(status::PARSE_ERROR),
    };
    match vk.verify_prehash(&session.tempkey.value, &sig) {
        Ok(()) => atca::status_response(status::SUCCESS),
        Err(_) => atca::status_response(status::MISCOMPARE),
    }
}
