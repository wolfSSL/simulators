/* sign.rs
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

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

use crate::frame::{build_error, build_response, status};
use crate::object_store::types::CurveKind;
use crate::object_store::Device;

const P256_DIGEST_SIZE: usize = 32;

/// Generate Signature command.
///
/// Wire (cmd body, NIST/Brainpool ECDSA):
///   `[slot 1B] [message_len 2B BE] [message ... pre-hashed digest]`
///
/// Wire (rsp body):
///   `[R_len 2B BE] [R 32B] [S_len 2B BE] [S 32B]` (P-256 case)
///
/// Service: `stsafea_ecc_generate_signature` --
/// services/stsafea/stsafea_ecc.c. wolfSSL passes a pre-computed digest of
/// the curve's coordinate size (32 bytes for P-256) as the message.
pub fn handle(device: &Device, body: &[u8]) -> Vec<u8> {
    if body.len() < 1 + 2 {
        return build_error(status::LENGTH_ERROR);
    }
    let slot = body[0];
    let msg_len = u16::from_be_bytes([body[1], body[2]]) as usize;
    if body.len() != 3 + msg_len {
        return build_error(status::LENGTH_ERROR);
    }
    let msg = &body[3..3 + msg_len];

    let Some(slot_entry) = device.ecc_slots.get(&slot) else {
        return build_error(status::INVALID_PARAMETER);
    };
    if slot_entry.curve != CurveKind::NistP256 {
        return build_error(status::INVALID_PARAMETER);
    }
    if slot_entry.private_key.len() != 32 {
        return build_error(status::INVALID_PARAMETER);
    }
    let Ok(signing) = SigningKey::from_slice(&slot_entry.private_key) else {
        return build_error(status::INVALID_PARAMETER);
    };

    // wolfSSL and STSELib both pass a 32-byte pre-hash for P-256 ECDSA.
    // Reject anything else rather than silently truncating or zero-
    // padding (which would mask caller bugs and could produce signatures
    // for digests with different high bits than the caller intended --
    // FIPS 186-5 6.4.1 specifies left-truncation, not right-zero-pad).
    if msg.len() != P256_DIGEST_SIZE {
        return build_error(status::INVALID_PARAMETER);
    }
    let signature: Signature = match signing.sign_prehash(msg) {
        Ok(s) => s,
        Err(_) => return build_error(status::UNEXPECTED_ERROR),
    };
    let bytes = signature.to_bytes();
    let r = &bytes[..32];
    let s = &bytes[32..];

    let mut rsp = Vec::with_capacity(2 + 32 + 2 + 32);
    rsp.extend_from_slice(&(32u16).to_be_bytes());
    rsp.extend_from_slice(r);
    rsp.extend_from_slice(&(32u16).to_be_bytes());
    rsp.extend_from_slice(s);
    build_response(status::OK, &rsp)
}
