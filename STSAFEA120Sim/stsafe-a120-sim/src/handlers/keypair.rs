/* keypair.rs
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

use p256::{ecdsa::SigningKey, SecretKey};
use rand::rngs::OsRng;

use crate::frame::{build_error, build_response, status};
use crate::handlers::{is_nist_p256, NIST_P256_CURVE_ID, POINT_REPRESENTATION_UNCOMPRESSED};
use crate::object_store::types::{CurveKind, EccSlot};
use crate::object_store::Device;

/// Generate Key Pair command.
///
/// Wire (cmd body, after the 1-byte cmd header):
///   `[attribute_tag 1B] [slot 1B] [usage_limit 2B BE] [filler 2B] [curve_id ...]`
///
/// Wire (rsp body, after status header, NIST/Brainpool path only):
///   `[point_repr 1B = 0x04]
///    [X_len 2B BE] [X 32B]
///    [Y_len 2B BE] [Y 32B]`
///
/// Service: `stsafea_generate_ecc_key_pair` --
/// services/stsafea/stsafea_asymmetric_key_slots.c.
pub fn handle(device: &mut Device, body: &[u8]) -> Vec<u8> {
    // Minimum: 1 (attr_tag) + 1 (slot) + 2 (usage) + 2 (filler) +
    // NIST_P256_CURVE_ID.len() == 16
    if body.len() < 6 + NIST_P256_CURVE_ID.len() {
        return build_error(status::LENGTH_ERROR);
    }

    let _attribute_tag = body[0];
    let slot = body[1];
    // [usage_limit 2B BE] [filler 2B] -- both intentionally ignored, see
    // EccSlot doc for rationale.
    let curve_id = &body[6..];

    if !is_nist_p256(curve_id) {
        return build_error(status::INVALID_PARAMETER);
    }

    let secret = SecretKey::random(&mut OsRng);
    let priv_bytes = secret.to_bytes();
    let signing = SigningKey::from(&secret);
    let pub_point = signing.verifying_key().to_encoded_point(false);
    let pub_bytes = pub_point.as_bytes();
    // pub_bytes is 0x04 || X(32) || Y(32) for uncompressed P-256.
    if pub_bytes.len() != 65 {
        return build_error(status::UNEXPECTED_ERROR);
    }
    let x = &pub_bytes[1..33];
    let y = &pub_bytes[33..65];

    device.ecc_slots.insert(
        slot,
        EccSlot {
            curve: CurveKind::NistP256,
            private_key: priv_bytes.to_vec(),
        },
    );

    let mut rsp = Vec::with_capacity(1 + 2 + 32 + 2 + 32);
    rsp.push(POINT_REPRESENTATION_UNCOMPRESSED);
    rsp.extend_from_slice(&(32u16).to_be_bytes());
    rsp.extend_from_slice(x);
    rsp.extend_from_slice(&(32u16).to_be_bytes());
    rsp.extend_from_slice(y);
    build_response(status::OK, &rsp)
}
