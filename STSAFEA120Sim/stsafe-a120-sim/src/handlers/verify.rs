/* verify.rs
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

use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};

use crate::handlers::POINT_REPRESENTATION_UNCOMPRESSED;

const P256_DIGEST_SIZE: usize = 32;

use crate::frame::{build_error, build_response, status};
use crate::handlers::{is_nist_p256, NIST_P256_CURVE_ID};

/// Verify Signature command (NIST P-256 ECDSA path).
///
/// Wire (cmd body):
///   `[subject 1B = 0x00] [curve_id 10B] [point_repr 1B = 0x04]
///    [X_len 2B BE] [X 32B] [Y_len 2B BE] [Y 32B]
///    [R_len 2B BE] [R 32B] [S_len 2B BE] [S 32B]
///    [message_len 2B BE] [message ...]`
///
/// Wire (rsp body): `[validity 1B]` -- 0x00 = invalid, 0x01 = valid.
///
/// Service: `stsafea_ecc_verify_signature` -- services/stsafea/stsafea_ecc.c.
pub fn handle(body: &[u8]) -> Vec<u8> {
    let mut p = 0usize;
    let need = |p: usize, n: usize, body: &[u8]| -> bool { p + n <= body.len() };

    if !need(p, 1, body) {
        return build_error(status::LENGTH_ERROR);
    }
    let _subject = body[p];
    p += 1;

    if !need(p, NIST_P256_CURVE_ID.len(), body) {
        return build_error(status::LENGTH_ERROR);
    }
    if !is_nist_p256(&body[p..p + NIST_P256_CURVE_ID.len()]) {
        return build_error(status::INVALID_PARAMETER);
    }
    p += NIST_P256_CURVE_ID.len();

    // Point representation byte: only uncompressed (0x04) is supported.
    // Real silicon decompresses on the fly via the extended Decompress
    // Public Key command, but the simulator does not implement that path.
    if !need(p, 1, body) {
        return build_error(status::LENGTH_ERROR);
    }
    if body[p] != POINT_REPRESENTATION_UNCOMPRESSED {
        return build_error(status::INVALID_PARAMETER);
    }
    p += 1;

    let pubkey = match read_xy(&body[p..]) {
        Some((xy, used)) => {
            p += used;
            xy
        }
        None => return build_error(status::LENGTH_ERROR),
    };

    let sig_rs = match read_rs(&body[p..]) {
        Some((rs, used)) => {
            p += used;
            rs
        }
        None => return build_error(status::LENGTH_ERROR),
    };

    if !need(p, 2, body) {
        return build_error(status::LENGTH_ERROR);
    }
    let msg_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if !need(p, msg_len, body) {
        return build_error(status::LENGTH_ERROR);
    }
    // Same constraint as the Sign handler: wolfSSL/STSELib hand us a
    // 32-byte P-256 pre-hash. Reject other lengths rather than silently
    // truncating or zero-padding.
    if msg_len != P256_DIGEST_SIZE {
        return build_error(status::INVALID_PARAMETER);
    }
    let digest: &[u8; 32] = body[p..p + msg_len].try_into().unwrap();

    let encoded = EncodedPoint::from_affine_coordinates(
        (&pubkey[..32]).into(),
        (&pubkey[32..]).into(),
        false,
    );
    let pk: PublicKey = match Option::from(PublicKey::from_encoded_point(&encoded)) {
        Some(p) => p,
        None => return build_response(status::OK, &[0]),
    };
    let verifying = VerifyingKey::from(&pk);
    let Ok(signature) = Signature::from_slice(&sig_rs) else {
        return build_response(status::OK, &[0]);
    };
    let valid = verifying.verify_prehash(digest, &signature).is_ok();
    build_response(status::OK, &[if valid { 1 } else { 0 }])
}

/// Parse `[X_len 2B BE] [X 32B] [Y_len 2B BE] [Y 32B]` and return `[X || Y]`
/// (64 bytes) plus the number of bytes consumed.
fn read_xy(buf: &[u8]) -> Option<([u8; 64], usize)> {
    if buf.len() < 2 + 32 + 2 + 32 {
        return None;
    }
    let xlen = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if xlen != 32 {
        return None;
    }
    let x = &buf[2..34];
    let ylen = u16::from_be_bytes([buf[34], buf[35]]) as usize;
    if ylen != 32 {
        return None;
    }
    let y = &buf[36..68];
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(x);
    out[32..].copy_from_slice(y);
    Some((out, 68))
}

/// Parse `[R_len 2B BE] [R 32B] [S_len 2B BE] [S 32B]` -> `[R || S]`.
fn read_rs(buf: &[u8]) -> Option<([u8; 64], usize)> {
    read_xy(buf)
}
