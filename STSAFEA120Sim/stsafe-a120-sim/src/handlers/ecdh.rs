/* ecdh.rs
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

use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint, PublicKey, SecretKey};

use crate::frame::{build_error, build_response, status};
use crate::handlers::POINT_REPRESENTATION_UNCOMPRESSED;
use crate::object_store::types::CurveKind;
use crate::object_store::Device;

/// Establish Key (ECDH) command for NIST P-256.
///
/// Wire (cmd body):
///   `[private_slot 1B] [point_repr 1B = 0x04]
///    [X_len 2B BE] [X 32B] [Y_len 2B BE] [Y 32B]`
///   (No curve_id field here -- the curve is implied by the slot's stored
///    key type. Matches `stsafea_ecc_establish_shared_secret`.)
///
/// Wire (rsp body):
///   `[shared_secret_len 2B BE] [secret 32B]`
///
/// Service: `stsafea_ecc_establish_shared_secret` --
/// services/stsafea/stsafea_ecc.c.
pub fn handle(device: &Device, body: &[u8]) -> Vec<u8> {
    if body.len() < 1 + 1 + 2 + 32 + 2 + 32 {
        return build_error(status::LENGTH_ERROR);
    }
    let slot = body[0];
    // Only uncompressed-affine (0x04) public keys are accepted. The
    // simulator does not implement the extended Decompress Public Key
    // command path, so a compressed peer key would otherwise be parsed
    // as a malformed X||Y blob.
    if body[1] != POINT_REPRESENTATION_UNCOMPRESSED {
        return build_error(status::INVALID_PARAMETER);
    }
    let xlen = u16::from_be_bytes([body[2], body[3]]) as usize;
    if xlen != 32 {
        return build_error(status::INVALID_PARAMETER);
    }
    let x = &body[4..36];
    let ylen = u16::from_be_bytes([body[36], body[37]]) as usize;
    if ylen != 32 {
        return build_error(status::INVALID_PARAMETER);
    }
    let y = &body[38..70];

    let Some(slot_entry) = device.ecc_slots.get(&slot) else {
        return build_error(status::INVALID_PARAMETER);
    };
    if slot_entry.curve != CurveKind::NistP256 {
        return build_error(status::INVALID_PARAMETER);
    }
    if slot_entry.private_key.len() != 32 {
        return build_error(status::INVALID_PARAMETER);
    }

    let Ok(secret) = SecretKey::from_slice(&slot_entry.private_key) else {
        return build_error(status::INVALID_PARAMETER);
    };
    let encoded = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let pubkey: PublicKey = match Option::from(PublicKey::from_encoded_point(&encoded)) {
        Some(p) => p,
        None => return build_error(status::INVALID_PARAMETER),
    };

    let pub_affine: AffinePoint = pubkey.as_affine().clone();
    let shared = diffie_hellman(secret.to_nonzero_scalar(), &pub_affine);
    let raw = shared.raw_secret_bytes();
    if raw.len() != 32 {
        return build_error(status::UNEXPECTED_ERROR);
    }

    let mut rsp = Vec::with_capacity(2 + 32);
    rsp.extend_from_slice(&(32u16).to_be_bytes());
    rsp.extend_from_slice(&raw);
    build_response(status::OK, &rsp)
}
