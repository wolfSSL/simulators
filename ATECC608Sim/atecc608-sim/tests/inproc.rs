/* inproc.rs
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

//! In-process integration tests that call `dispatch()` directly.
//!
//! These cover the full command pipeline (framing + parsing + handler logic +
//! response building) without going through TCP. Most coverage lives here
//! because it's fast and deterministic.

use atecc608_sim::atca::{status, WAKE_RESPONSE};
use atecc608_sim::crc::crc16_le;
use atecc608_sim::dispatch::{self, opcode};
use atecc608_sim::object_store::default_device;
use atecc608_sim::session::Session;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use p256::EncodedPoint;

fn make_cmd(op: u8, p1: u8, p2: u16, data: &[u8]) -> Vec<u8> {
    let count = (7 + data.len()) as u8;
    let mut pkt = vec![count, op, p1, (p2 & 0xFF) as u8, (p2 >> 8) as u8];
    pkt.extend_from_slice(data);
    pkt.extend_from_slice(&crc16_le(&pkt));
    pkt
}

fn dispatch_one(device: &mut atecc608_sim::Device, session: &mut Session, cmd: &[u8]) -> Vec<u8> {
    dispatch::dispatch(device, session, cmd)
}

#[test]
fn wake_response_bytes() {
    assert_eq!(WAKE_RESPONSE, [0x04, 0x11, 0x33, 0x43]);
}

#[test]
fn info_returns_revision() {
    let mut d = default_device();
    let mut s = Session::new();
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::INFO, 0x00, 0x0000, &[]));
    // count(1) + 4 bytes revision + crc(2) = 7
    assert_eq!(r.len(), 7);
    assert_eq!(r[0], 7);
    assert_eq!(&r[1..5], &[0x00, 0x00, 0x60, 0x02]);
}

#[test]
fn random_returns_32_bytes() {
    let mut d = default_device();
    let mut s = Session::new();
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::RANDOM, 0x00, 0x0000, &[]));
    assert_eq!(r.len(), 35); // 1 + 32 + 2
    assert_eq!(r[0], 35);
    // Two calls should return different randomness with overwhelming probability
    let r2 = dispatch_one(&mut d, &mut s, &make_cmd(opcode::RANDOM, 0x00, 0x0000, &[]));
    assert_ne!(&r[1..33], &r2[1..33]);
}

#[test]
fn read_config_zone_returns_known_bytes() {
    let mut d = default_device();
    let mut s = Session::new();
    // 32-byte read of config zone block 0 (SN + revision).
    // P1 = 0x80 (32-byte) | 0x00 (config zone) = 0x80. P2 = addr 0 = block 0.
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::READ, 0x80, 0x0000, &[]));
    assert_eq!(r.len(), 35);
    assert_eq!(r[0], 35);
    // First two bytes of config are the fixed SN prefix {0x01, 0x23}.
    assert_eq!(&r[1..3], &[0x01, 0x23]);
    // Bytes 4..8 are the revision word.
    assert_eq!(&r[5..9], &[0x00, 0x00, 0x60, 0x02]);
}

#[test]
fn read_lock_bytes_shows_locked() {
    let mut d = default_device();
    let mut s = Session::new();
    // 4-byte read of config bytes at byte offset 84 = block 2 offset 5 (words).
    // addr = (block << 3) | offset = (2 << 3) | 5 = 0x15. P1=0x00 (4-byte, config).
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::READ, 0x00, 0x0015, &[]));
    assert_eq!(r.len(), 7);
    // 4 bytes read; bytes 86 and 87 should be 0x00 (locked).
    // block 2 = bytes 64..96. offset 5 words = bytes 20..24 within block = bytes 84..88.
    let chunk = &r[1..5]; // config[84..88]
    assert_eq!(chunk[2], 0x00, "LockValue (config[86]) expected 0x00 = locked");
    assert_eq!(chunk[3], 0x00, "LockConfig (config[87]) expected 0x00 = locked");
}

#[test]
fn write_config_rejected_when_locked() {
    let mut d = default_device();
    let mut s = Session::new();
    // 4-byte write to config bytes 0..4 (config zone is locked by default).
    let r = dispatch_one(
        &mut d,
        &mut s,
        &make_cmd(opcode::WRITE, 0x00, 0x0000, &[0xDE, 0xAD, 0xBE, 0xEF]),
    );
    assert_eq!(r.len(), 4);
    assert_eq!(r[1], status::EXECUTION_ERROR);
}

#[test]
fn lock_rejected_when_already_locked() {
    let mut d = default_device();
    let mut s = Session::new();
    // Config-zone lock on an already-locked device returns EXECUTION_ERROR.
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::LOCK, 0x80, 0x0000, &[]));
    assert_eq!(r[1], status::EXECUTION_ERROR);
}

#[test]
fn sha_oneshot_matches_reference() {
    let mut d = default_device();
    let mut s = Session::new();
    let input = b"hello world";
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::SHA, 0x03, input.len() as u16, input));
    // Expected SHA-256("hello world")
    let expected = hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        .unwrap();
    assert_eq!(&r[1..33], &expected[..]);
}

#[test]
fn sha_multistep_matches_oneshot() {
    let mut d = default_device();
    let mut s = Session::new();
    let input = b"The quick brown fox jumps over the lazy dog";
    // Start
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::SHA, 0x00, 0x0000, &[]));
    assert_eq!(r[1], status::SUCCESS);
    // Update with first 32 bytes (cryptoauthlib uses 64-byte blocks but any
    // size is fine for the simulator since we absorb directly).
    let r = dispatch_one(
        &mut d,
        &mut s,
        &make_cmd(opcode::SHA, 0x01, input[..32].len() as u16, &input[..32]),
    );
    assert_eq!(r[1], status::SUCCESS);
    // End with the remainder as the trailing chunk.
    let r = dispatch_one(
        &mut d,
        &mut s,
        &make_cmd(opcode::SHA, 0x02, input[32..].len() as u16, &input[32..]),
    );
    let expected =
        hex::decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").unwrap();
    assert_eq!(&r[1..33], &expected[..]);
}

#[test]
fn nonce_passthrough_loads_tempkey() {
    let mut d = default_device();
    let mut s = Session::new();
    let msg = [0x42u8; 32];
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::NONCE, 0x03, 0x0000, &msg));
    assert_eq!(r[1], status::SUCCESS);
    assert!(s.tempkey.valid);
    assert_eq!(s.tempkey.value, msg);
}

#[test]
fn sign_without_tempkey_rejected() {
    let mut d = default_device();
    let mut s = Session::new();
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::SIGN, 0x80, 0x0000, &[]));
    assert_eq!(r[1], status::EXECUTION_ERROR);
}

#[test]
fn genkey_sign_verify_round_trip() {
    let mut d = default_device();
    let mut s = Session::new();

    // 1. Generate private key in slot 0, get 64-byte pubkey back.
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::GENKEY, 0x04, 0x0000, &[]));
    assert_eq!(r.len(), 67, "genkey response = count(1) + 64 + crc(2)");
    let pk: [u8; 64] = r[1..65].try_into().unwrap();

    // 2. Load a message digest into TempKey via pass-through Nonce.
    let digest = [0x7Au8; 32];
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::NONCE, 0x03, 0x0000, &digest));
    assert_eq!(r[1], status::SUCCESS);

    // 3. Sign using slot 0.
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::SIGN, 0x80, 0x0000, &[]));
    assert_eq!(r.len(), 67, "sign response = count(1) + 64 + crc(2); got {:?}", r);
    let sig_bytes: [u8; 64] = r[1..65].try_into().unwrap();

    // 4. Independently verify via p256 using the returned pubkey.
    let point = EncodedPoint::from_untagged_bytes(&pk.into());
    let vk = VerifyingKey::from_encoded_point(&point).expect("valid pubkey");
    let sig = Signature::try_from(&sig_bytes[..]).expect("valid sig encoding");
    vk.verify_prehash(&digest, &sig).expect("signature must verify");

    // 5. Also verify through the simulator's Verify command (external mode).
    // Reload the digest into TempKey (consumed state is still there — Verify
    // uses same TempKey).
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&sig_bytes);
    data.extend_from_slice(&pk);
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::VERIFY, 0x02, 0x0000, &data));
    assert_eq!(r[1], status::SUCCESS);

    // 6. Flip a byte in the signature and confirm verify rejects.
    let mut bad_data = data.clone();
    bad_data[0] ^= 0xFF;
    // Reload TempKey to avoid state churn.
    dispatch_one(&mut d, &mut s, &make_cmd(opcode::NONCE, 0x03, 0x0000, &digest));
    let r = dispatch_one(&mut d, &mut s, &make_cmd(opcode::VERIFY, 0x02, 0x0000, &bad_data));
    assert_eq!(r[1], status::MISCOMPARE);
}

#[test]
fn ecdh_shared_secret_symmetric() {
    let mut d = default_device();
    let mut s = Session::new();

    // Generate two keypairs in slots 0 and 1.
    let r_a = dispatch_one(&mut d, &mut s, &make_cmd(opcode::GENKEY, 0x04, 0x0000, &[]));
    let pk_a: [u8; 64] = r_a[1..65].try_into().unwrap();
    let r_b = dispatch_one(&mut d, &mut s, &make_cmd(opcode::GENKEY, 0x04, 0x0001, &[]));
    let pk_b: [u8; 64] = r_b[1..65].try_into().unwrap();

    // ECDH in slot 0 with peer pubkey = pk_b
    let r1 = dispatch_one(&mut d, &mut s, &make_cmd(opcode::ECDH, 0x00, 0x0000, &pk_b));
    assert_eq!(r1.len(), 35);
    // ECDH in slot 1 with peer pubkey = pk_a
    let r2 = dispatch_one(&mut d, &mut s, &make_cmd(opcode::ECDH, 0x00, 0x0001, &pk_a));
    assert_eq!(r2.len(), 35);

    // Both sides derive the same shared secret.
    assert_eq!(&r1[1..33], &r2[1..33]);
}

#[test]
fn bad_opcode_returns_parse_error() {
    let mut d = default_device();
    let mut s = Session::new();
    let r = dispatch_one(&mut d, &mut s, &make_cmd(0xAB, 0, 0, &[]));
    assert_eq!(r[1], status::PARSE_ERROR);
}

#[test]
fn bad_crc_returns_crc_error() {
    let mut d = default_device();
    let mut s = Session::new();
    let mut pkt = make_cmd(opcode::INFO, 0, 0, &[]);
    *pkt.last_mut().unwrap() ^= 0xFF;
    let r = dispatch_one(&mut d, &mut s, &pkt);
    assert_eq!(r[1], status::CRC_ERROR);
}
