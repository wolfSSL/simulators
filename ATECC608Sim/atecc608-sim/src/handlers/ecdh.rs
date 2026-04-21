/* ecdh.rs
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
use crate::handlers::genkey::slot_scalar;
use crate::object_store::{Device, NUM_SLOTS};
use crate::session::Session;
use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::FromEncodedPoint,
    EncodedPoint, NonZeroScalar, PublicKey, SecretKey,
};

/// ECDH command (opcode 0x43).
///
/// P1 mode:
///   0x00 = Output in clear (32-byte shared X, unencrypted). This is the
///          path wolfSSL uses by default.
///   0x08 / 0x0C = Encrypted output / output-to-slot. Not implemented.
/// P2 = private key slot.
/// Data = 64-byte peer public key (X || Y, no prefix).
/// Response = 32-byte shared X coordinate.
pub fn handle(device: &Device, _session: &mut Session, cmd: &Command) -> Vec<u8> {
    if cmd.p1 != 0x00 {
        return atca::status_response(status::EXECUTION_ERROR);
    }
    let slot = cmd.p2 as usize;
    if slot >= NUM_SLOTS {
        return atca::status_response(status::PARSE_ERROR);
    }
    if cmd.data.len() != 64 {
        return atca::status_response(status::PARSE_ERROR);
    }
    let scalar_bytes = match slot_scalar(device, slot) {
        Some(s) => s,
        None => return atca::status_response(status::EXECUTION_ERROR),
    };
    let sk = match SecretKey::from_bytes(&scalar_bytes.into()) {
        Ok(s) => s,
        Err(_) => return atca::status_response(status::EXECUTION_ERROR),
    };
    let peer_point = EncodedPoint::from_untagged_bytes(cmd.data[..64].into());
    let peer_pk = match PublicKey::from_encoded_point(&peer_point).into() {
        Some(pk) => pk,
        None => return atca::status_response(status::PARSE_ERROR),
    };
    let nz: NonZeroScalar = sk.to_nonzero_scalar();
    let shared = diffie_hellman(nz, PublicKey::as_affine(&peer_pk));
    let raw = shared.raw_secret_bytes();
    let raw_bytes: &[u8] = raw.as_ref();
    atca::build_response(raw_bytes)
}
