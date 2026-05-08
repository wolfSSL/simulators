/* l3.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of TROPIC01Sim.
 *
 * TROPIC01Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * TROPIC01Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// L3 plaintext command dispatcher. Each L3 command is `[cmd_id (1B)] +
/// fields...` after AES-GCM open; the response is `[result (1B)] +
/// fields...` before AES-GCM seal. cmd_id values are from
/// `lt_l3_api_structs.h`.
///
/// L3 result codes (`lt_l3_process.h`):
///   OK           = 0xC3
///   FAIL         = 0x3C
///   UNAUTHORIZED = 0x01
///   INVALID_CMD  = 0x02
use ed25519_dalek::SigningKey as Ed25519Signing;
use p256::{
    elliptic_curve::sec1::ToEncodedPoint, EncodedPoint as P256EncodedPoint, SecretKey as P256Secret,
};
use rand::rngs::OsRng;
use rand_core::RngCore;

use crate::object_store::{
    types::{CurveKind, EccSlot, KeyOrigin, PairingSlot, RMemSlot},
    Device,
};

pub mod result {
    pub const OK: u8 = 0xC3;
    pub const FAIL: u8 = 0x3C;
    pub const UNAUTHORIZED: u8 = 0x01;
    pub const INVALID_CMD: u8 = 0x02;
}

pub mod cmd_id {
    pub const PING: u8 = 0x01;
    pub const PAIRING_KEY_WRITE: u8 = 0x10;
    pub const PAIRING_KEY_READ: u8 = 0x11;
    pub const PAIRING_KEY_INVALIDATE: u8 = 0x12;
    pub const R_MEM_DATA_WRITE: u8 = 0x40;
    pub const R_MEM_DATA_READ: u8 = 0x41;
    pub const RANDOM_VALUE_GET: u8 = 0x50;
    pub const ECC_KEY_GENERATE: u8 = 0x60;
    pub const ECC_KEY_STORE: u8 = 0x61;
    pub const ECC_KEY_READ: u8 = 0x62;
    pub const ECC_KEY_ERASE: u8 = 0x63;
}

const ED25519_PUBKEY_LEN: usize = 32;
const P256_PUBKEY_LEN: usize = 64;

/// Maximum R_MEM slot payload that can round-trip through the L2/L3 stack.
/// An R_MEM_DATA_READ response is wrapped as
/// `[cmd_size(2)] [ [result(1)][padding(3)][data] ] [tag(16)]` = 22 + data_len
/// bytes, and that buffer becomes the L2 data field whose RSP_LEN is u8 and
/// whose hard cap is `MAX_L2_DATA_SIZE = 252`. So data_len is bounded by
/// 252 - 22 = 230.
const MAX_R_MEM_DATA_SIZE: usize = 230;

pub fn dispatch(device: &mut Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.is_empty() {
        return single_byte(result::INVALID_CMD);
    }
    match plaintext[0] {
        cmd_id::PING => ping(plaintext),
        cmd_id::PAIRING_KEY_WRITE => pairing_key_write(device, plaintext),
        cmd_id::PAIRING_KEY_READ => pairing_key_read(device, plaintext),
        cmd_id::PAIRING_KEY_INVALIDATE => pairing_key_invalidate(device, plaintext),
        cmd_id::R_MEM_DATA_WRITE => r_mem_data_write(device, plaintext),
        cmd_id::R_MEM_DATA_READ => r_mem_data_read(device, plaintext),
        cmd_id::RANDOM_VALUE_GET => random_value_get(plaintext),
        cmd_id::ECC_KEY_GENERATE => ecc_key_generate(device, plaintext),
        cmd_id::ECC_KEY_STORE => ecc_key_store(device, plaintext),
        cmd_id::ECC_KEY_READ => ecc_key_read(device, plaintext),
        cmd_id::ECC_KEY_ERASE => ecc_key_erase(device, plaintext),
        _ => single_byte(result::INVALID_CMD),
    }
}

fn single_byte(code: u8) -> Vec<u8> {
    vec![code]
}

/// PING: `[0x01][data_in...]` -> `[0xC3][data_in...]`.
fn ping(plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len());
    out.push(result::OK);
    out.extend_from_slice(&plaintext[1..]);
    out
}

/// PAIRING_KEY_WRITE: `[0x10][slot u16 LE][padding 1B][s_hipub 32B]`
/// (cmd_size = 36) -> `[result 1B]`.
fn pairing_key_write(device: &mut Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 36 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    if slot > 3 {
        return single_byte(result::FAIL);
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&plaintext[4..36]);
    device.pairing_slots.insert(
        slot as u8,
        PairingSlot {
            public_key: pubkey,
            is_valid: true,
        },
    );
    single_byte(result::OK)
}

/// PAIRING_KEY_READ: `[0x11][slot u16 LE]` -> `[result 1B][padding 3B][s_hipub 32B]` (res_size=36).
fn pairing_key_read(device: &Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 3 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    let Some(entry) = device.pairing_slots.get(&(slot as u8)) else {
        return single_byte(result::FAIL);
    };
    if !entry.is_valid {
        return single_byte(result::UNAUTHORIZED);
    }
    let mut out = Vec::with_capacity(36);
    out.push(result::OK);
    out.extend_from_slice(&[0u8; 3]); // padding
    out.extend_from_slice(&entry.public_key);
    out
}

/// PAIRING_KEY_INVALIDATE: `[0x12][slot u16 LE]` -> `[result 1B]`.
fn pairing_key_invalidate(device: &mut Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 3 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    match device.pairing_slots.get_mut(&(slot as u8)) {
        Some(entry) => {
            entry.is_valid = false;
            single_byte(result::OK)
        }
        None => single_byte(result::FAIL),
    }
}

/// R_MEM_DATA_WRITE: `[0x40][udata_slot u16 LE][padding 1B][data...]`
/// (cmd_size_min = 5) -> `[result 1B]`.
fn r_mem_data_write(device: &mut Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() < 5 {
        return single_byte(result::FAIL);
    }
    let data_len = plaintext.len() - 4;
    if data_len > MAX_R_MEM_DATA_SIZE {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    let data = plaintext[4..].to_vec();
    device.r_mem_slots.insert(slot, RMemSlot { data });
    single_byte(result::OK)
}

/// R_MEM_DATA_READ: `[0x41][udata_slot u16 LE]` -> `[result 1B][padding 3B][data...]`
/// (res_size = 4 + data_len).
fn r_mem_data_read(device: &Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 3 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    let Some(entry) = device.r_mem_slots.get(&slot) else {
        return single_byte(result::FAIL);
    };
    if entry.data.len() > MAX_R_MEM_DATA_SIZE {
        // Stale persisted slot is too large to encode in a single L2 frame.
        // Better to FAIL cleanly than panic in build_response further up.
        return single_byte(result::FAIL);
    }
    let mut out = Vec::with_capacity(4 + entry.data.len());
    out.push(result::OK);
    out.extend_from_slice(&[0u8; 3]); // padding
    out.extend_from_slice(&entry.data);
    out
}

/// RANDOM_VALUE_GET: `[0x50][n_bytes 1B]` -> `[result 1B][padding 3B][random n_bytes]`
/// (res_size = 4 + n; max n = 255).
fn random_value_get(plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 2 {
        return single_byte(result::FAIL);
    }
    let n = plaintext[1] as usize;
    if n > 255 {
        return single_byte(result::FAIL);
    }
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    let mut out = Vec::with_capacity(4 + n);
    out.push(result::OK);
    out.extend_from_slice(&[0u8; 3]); // padding
    out.extend_from_slice(&bytes);
    out
}

/// ECC_KEY_GENERATE: `[0x60][slot u16 LE][curve 1B]` (cmd_size = 4) -> `[result 1B]`.
fn ecc_key_generate(device: &mut Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 4 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    let Some(curve) = CurveKind::from_wire_id(plaintext[3]) else {
        return single_byte(result::FAIL);
    };
    let key = generate_private_key(curve);
    device.ecc_slots.insert(
        slot,
        EccSlot {
            curve,
            origin: KeyOrigin::Generated,
            private_key: key,
        },
    );
    single_byte(result::OK)
}

/// ECC_KEY_STORE: `[0x61][slot u16 LE][curve 1B][padding 12B][k 32B]`
/// (cmd_size = 48) -> `[result 1B]`.
fn ecc_key_store(device: &mut Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 48 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    let Some(curve) = CurveKind::from_wire_id(plaintext[3]) else {
        return single_byte(result::FAIL);
    };
    let key = plaintext[16..48].to_vec();
    device.ecc_slots.insert(
        slot,
        EccSlot {
            curve,
            origin: KeyOrigin::Stored,
            private_key: key,
        },
    );
    single_byte(result::OK)
}

/// ECC_KEY_READ: `[0x62][slot u16 LE]` -> `[result 1B][curve 1B][origin 1B][padding 13B][pub_key]`
/// where pub_key is 32B for Ed25519 (res_size = 48) or 64B for P-256 (res_size = 80).
fn ecc_key_read(device: &Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 3 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    let Some(entry) = device.ecc_slots.get(&slot) else {
        return single_byte(result::FAIL);
    };
    let pubkey = match derive_public_key(entry) {
        Some(p) => p,
        None => return single_byte(result::FAIL),
    };
    let mut out = Vec::with_capacity(16 + pubkey.len());
    out.push(result::OK);
    out.push(entry.curve.wire_id());
    out.push(entry.origin.wire_id());
    out.extend_from_slice(&[0u8; 13]); // padding
    out.extend_from_slice(&pubkey);
    out
}

/// ECC_KEY_ERASE: `[0x63][slot u16 LE]` -> `[result 1B]`.
fn ecc_key_erase(device: &mut Device, plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() != 3 {
        return single_byte(result::FAIL);
    }
    let slot = u16::from_le_bytes([plaintext[1], plaintext[2]]);
    device.ecc_slots.remove(&slot);
    single_byte(result::OK)
}

fn generate_private_key(curve: CurveKind) -> Vec<u8> {
    match curve {
        CurveKind::Ed25519 => {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            // Ed25519 private keys are arbitrary 32 bytes (the seed); no clamping needed at storage.
            k.to_vec()
        }
        CurveKind::P256 => {
            let secret = P256Secret::random(&mut OsRng);
            secret.to_bytes().to_vec()
        }
    }
}

fn derive_public_key(slot: &EccSlot) -> Option<Vec<u8>> {
    match slot.curve {
        CurveKind::Ed25519 => {
            let bytes: [u8; 32] = slot.private_key.as_slice().try_into().ok()?;
            let signing = Ed25519Signing::from_bytes(&bytes);
            Some(signing.verifying_key().to_bytes().to_vec())
        }
        CurveKind::P256 => {
            let secret = P256Secret::from_slice(&slot.private_key).ok()?;
            let pt: P256EncodedPoint = secret.public_key().to_encoded_point(false);
            // pt is `[0x04 | X(32) | Y(32)]` (uncompressed). Strip the
            // leading 0x04 so the on-wire pub_key is the raw 64-byte
            // X||Y form `lt_in__ecc_key_read` checks against
            // `TR01_CURVE_P256_PUBKEY_LEN = 64`.
            let bytes = pt.as_bytes();
            if bytes.len() != 65 || bytes[0] != 0x04 {
                return None;
            }
            Some(bytes[1..].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::Store;

    #[test]
    fn ping_echoes_payload() {
        let payload = [cmd_id::PING, 1, 2, 3, 4];
        let mut store = Store::fresh();
        let resp = dispatch(&mut store.device, &payload);
        assert_eq!(resp, vec![result::OK, 1, 2, 3, 4]);
    }

    #[test]
    fn random_returns_n_bytes() {
        let mut store = Store::fresh();
        let resp = dispatch(&mut store.device, &[cmd_id::RANDOM_VALUE_GET, 16]);
        assert_eq!(resp.len(), 4 + 16);
        assert_eq!(resp[0], result::OK);
    }

    #[test]
    fn r_mem_read_returns_fixture() {
        let mut store = Store::fresh();
        let resp = dispatch(
            &mut store.device,
            &[cmd_id::R_MEM_DATA_READ, 0x00, 0x00],
        );
        assert_eq!(resp[0], result::OK);
        assert_eq!(resp.len(), 4 + 32); // padding(3) + 32 bytes of AES key fixture
    }

    #[test]
    fn r_mem_write_then_read() {
        let mut store = Store::fresh();
        let mut write = vec![cmd_id::R_MEM_DATA_WRITE, 0x05, 0x00, 0x00];
        write.extend_from_slice(b"hello world!");
        let resp = dispatch(&mut store.device, &write);
        assert_eq!(resp, vec![result::OK]);
        let read = dispatch(
            &mut store.device,
            &[cmd_id::R_MEM_DATA_READ, 0x05, 0x00],
        );
        assert_eq!(&read[4..], b"hello world!");
    }

    #[test]
    fn ecc_keygen_then_read_ed25519() {
        let mut store = Store::fresh();
        let gen = dispatch(
            &mut store.device,
            &[
                cmd_id::ECC_KEY_GENERATE,
                0x01,
                0x00,
                CurveKind::Ed25519.wire_id(),
            ],
        );
        assert_eq!(gen, vec![result::OK]);
        let read = dispatch(
            &mut store.device,
            &[cmd_id::ECC_KEY_READ, 0x01, 0x00],
        );
        // [result(1)][curve(1)][origin(1)][padding(13)][pub(32)]
        assert_eq!(read.len(), 48);
        assert_eq!(read[0], result::OK);
        assert_eq!(read[1], CurveKind::Ed25519.wire_id());
        assert_eq!(read[2], KeyOrigin::Generated.wire_id());
    }

    #[test]
    fn ecc_keygen_then_read_p256() {
        let mut store = Store::fresh();
        let gen = dispatch(
            &mut store.device,
            &[
                cmd_id::ECC_KEY_GENERATE,
                0x02,
                0x00,
                CurveKind::P256.wire_id(),
            ],
        );
        assert_eq!(gen, vec![result::OK]);
        let read = dispatch(
            &mut store.device,
            &[cmd_id::ECC_KEY_READ, 0x02, 0x00],
        );
        // [result(1)][curve(1)][origin(1)][padding(13)][pub(64)]
        assert_eq!(read.len(), 80);
        assert_eq!(read[0], result::OK);
        assert_eq!(read[1], CurveKind::P256.wire_id());
    }

    #[test]
    fn ecc_erase_clears_slot() {
        let mut store = Store::fresh();
        dispatch(
            &mut store.device,
            &[
                cmd_id::ECC_KEY_GENERATE,
                0x03,
                0x00,
                CurveKind::Ed25519.wire_id(),
            ],
        );
        let erase = dispatch(
            &mut store.device,
            &[cmd_id::ECC_KEY_ERASE, 0x03, 0x00],
        );
        assert_eq!(erase, vec![result::OK]);
        let read = dispatch(
            &mut store.device,
            &[cmd_id::ECC_KEY_READ, 0x03, 0x00],
        );
        assert_eq!(read, vec![result::FAIL]);
    }

    #[test]
    fn pairing_read_returns_fixture() {
        let mut store = Store::fresh();
        let resp = dispatch(
            &mut store.device,
            &[cmd_id::PAIRING_KEY_READ, 0x00, 0x00],
        );
        assert_eq!(resp.len(), 36);
        assert_eq!(resp[0], result::OK);
        assert_eq!(
            &resp[4..36],
            &crate::object_store::default_host_pairing_pub()
        );
    }

    #[test]
    fn pairing_invalidate_blocks_subsequent_read() {
        let mut store = Store::fresh();
        let inv = dispatch(
            &mut store.device,
            &[cmd_id::PAIRING_KEY_INVALIDATE, 0x00, 0x00],
        );
        assert_eq!(inv, vec![result::OK]);
        let read = dispatch(
            &mut store.device,
            &[cmd_id::PAIRING_KEY_READ, 0x00, 0x00],
        );
        assert_eq!(read[0], result::UNAUTHORIZED);
    }

    #[test]
    fn unknown_cmd_returns_invalid_cmd() {
        let mut store = Store::fresh();
        let resp = dispatch(&mut store.device, &[0xFE]);
        assert_eq!(resp, vec![result::INVALID_CMD]);
    }

    #[test]
    fn r_mem_write_rejects_oversized_payload() {
        let mut store = Store::fresh();
        let mut write = vec![cmd_id::R_MEM_DATA_WRITE, 0x06, 0x00, 0x00];
        write.extend(std::iter::repeat(0xAB).take(MAX_R_MEM_DATA_SIZE + 1));
        let resp = dispatch(&mut store.device, &write);
        assert_eq!(resp, vec![result::FAIL]);
    }

    #[test]
    fn r_mem_read_fails_when_slot_too_large() {
        let mut store = Store::fresh();
        store.device.r_mem_slots.insert(
            0x07,
            RMemSlot {
                data: vec![0xCD; MAX_R_MEM_DATA_SIZE + 1],
            },
        );
        let resp = dispatch(
            &mut store.device,
            &[cmd_id::R_MEM_DATA_READ, 0x07, 0x00],
        );
        assert_eq!(resp, vec![result::FAIL]);
    }
}
