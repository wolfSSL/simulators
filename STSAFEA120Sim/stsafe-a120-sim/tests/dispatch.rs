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

//! End-to-end dispatch tests exercising each handler with byte-level
//! command frames matching what STSELib would actually push on the wire.

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::rngs::OsRng;

use stsafe_a120_sim::dispatch;
use stsafe_a120_sim::frame::{build_command, build_response, parse_command, status, FrameError};
use stsafe_a120_sim::object_store::{Store, DEVICE_CERT_ZONE};
use stsafe_a120_sim::session::Session;

const NIST_P256_CURVE_ID: [u8; 10] = [
    0x00, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
];

/// Run dispatch and parse the response, returning (status, body).
fn round_trip(store: &mut Store, session: &mut Session, frame: &[u8]) -> (u8, Vec<u8>) {
    let resp = dispatch(store, session, frame);
    // Strip header(1) + length(2) + CRC(2) for inspection.
    assert!(resp.len() >= 5);
    let length = u16::from_be_bytes([resp[1], resp[2]]) as usize;
    assert_eq!(length, resp.len() - 3);
    let body = resp[3..resp.len() - 2].to_vec();
    (resp[0] & 0x1F, body)
}

#[test]
fn echo_round_trips_payload() {
    let mut store = Store::fresh();
    let mut session = Session::new();
    let payload = b"hello stsafe".to_vec();
    let cmd = build_command(0x00, &payload);
    let (st, body) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    assert_eq!(body, payload);
}

#[test]
fn random_returns_requested_size() {
    let mut store = Store::fresh();
    let mut session = Session::new();
    let cmd = build_command(0x02, &[0x00, 32]);
    let (st, body) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    assert_eq!(body.len(), 32);

    // Two consecutive draws should differ (negligible chance of collision).
    let cmd2 = build_command(0x02, &[0x00, 32]);
    let (_, body2) = round_trip(&mut store, &mut session, &cmd2);
    assert_ne!(body, body2);
}

#[test]
fn random_rejects_zero_size() {
    let mut store = Store::fresh();
    let mut session = Session::new();
    let cmd = build_command(0x02, &[0x00, 0]);
    let (st, _) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::INVALID_PARAMETER);
}

#[test]
fn bad_crc_returns_crc_error() {
    let mut store = Store::fresh();
    let mut session = Session::new();
    let mut cmd = build_command(0x02, &[0x00, 16]);
    let last = cmd.len() - 1;
    cmd[last] ^= 0xFF;
    let (st, _) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::CRC_ERROR);
}

#[test]
fn unknown_opcode_returns_command_not_supported() {
    let mut store = Store::fresh();
    let mut session = Session::new();
    let cmd = build_command(0x7E, &[]);
    let (st, _) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::COMMAND_CODE_NOT_SUPPORTED);
}

#[test]
fn extended_command_returns_command_not_supported() {
    let mut store = Store::fresh();
    let mut session = Session::new();
    // Extended prefix + arbitrary extended opcode
    let cmd = build_command_2byte_header(0x1F, 0x05, &[]);
    let (st, _) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::COMMAND_CODE_NOT_SUPPORTED);
}

fn build_command_2byte_header(prefix: u8, ext: u8, body: &[u8]) -> Vec<u8> {
    let mut full = Vec::with_capacity(2 + body.len());
    full.push(prefix);
    full.push(ext);
    full.extend_from_slice(body);
    let crc = stsafe_a120_sim::frame::build_command(0, &[]);
    // Trick: just build with a 1-byte header and rebuild the CRC ourselves.
    let _ = crc;
    let mut frame = Vec::new();
    frame.push(prefix);
    frame.push(ext);
    frame.extend_from_slice(body);
    let crc = crc16_x25(&frame);
    frame.extend_from_slice(&crc.to_be_bytes());
    frame
}

fn crc16_x25(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in buf {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[test]
fn read_returns_device_certificate_bytes() {
    let mut store = Store::fresh();
    let mut session = Session::new();

    // Read 4 bytes from offset 0 of zone DEVICE_CERT_ZONE -- this is what
    // wolfSSL's SSL_STSAFE_LoadDeviceCertificate does first to discover
    // the certificate length.
    let zone = DEVICE_CERT_ZONE;
    let mut body = Vec::new();
    body.push(0x00); // option
    body.push(zone); // 1-byte zone form
    body.extend_from_slice(&0u16.to_be_bytes()); // offset
    body.extend_from_slice(&4u16.to_be_bytes()); // length
    let cmd = build_command(0x05, &body);
    let (st, data) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    assert_eq!(data.len(), 4);
    // First byte of the minimal certificate is 0x30 (DER SEQUENCE).
    assert_eq!(data[0], 0x30);
    assert_eq!(data[1], 0x82);
}

#[test]
fn generate_key_then_sign_and_verify_with_independent_pubkey() {
    let mut store = Store::fresh();
    let mut session = Session::new();

    // Generate a fresh keypair into slot 1.
    let slot = 1u8;
    let mut body = Vec::new();
    body.push(0x13); // attribute_tag = STSAFEA_SUBJECT_TAG_PRIVATE_KEY_SLOT (0x13)
    body.push(slot);
    body.extend_from_slice(&0u16.to_be_bytes()); // usage_limit = 0 (unlimited)
    body.extend_from_slice(&[0u8; 2]); // filler
    body.extend_from_slice(&NIST_P256_CURVE_ID);
    let cmd = build_command(0x11, &body);
    let (st, body) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    // [point_repr 1B][X_len 2B][X 32B][Y_len 2B][Y 32B] = 69 bytes
    assert_eq!(body.len(), 69);
    assert_eq!(body[0], 0x04);

    // Pull X || Y for an independent OpenSSL-style verify via p256.
    let x = &body[3..35];
    let y = &body[37..69];
    let mut pubraw = [0u8; 65];
    pubraw[0] = 0x04;
    pubraw[1..33].copy_from_slice(x);
    pubraw[33..].copy_from_slice(y);
    let verifying =
        VerifyingKey::from_sec1_bytes(&pubraw).expect("public key reconstructs from X||Y");

    // Now ask the simulator to sign a digest with that slot.
    let digest = [0xAA; 32];
    let mut body = Vec::new();
    body.push(slot);
    body.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    body.extend_from_slice(&digest);
    let cmd = build_command(0x16, &body);
    let (st, body) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    // Response: [R_len 2B][R 32B][S_len 2B][S 32B] = 68 bytes
    assert_eq!(body.len(), 68);
    let r = &body[2..34];
    let s = &body[36..68];
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let signature = Signature::from_slice(&sig_bytes).unwrap();
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    verifying
        .verify_prehash(&digest, &signature)
        .expect("ECDSA verifies under reconstructed public key");
}

#[test]
fn verify_signature_handler_accepts_correct_and_rejects_tampered() {
    let mut store = Store::fresh();
    let mut session = Session::new();

    // Generate an off-device keypair, sign a digest, then ask the
    // simulator to verify it.
    let secret = SecretKey::random(&mut OsRng);
    let signing = SigningKey::from(&secret);
    let pub_point = signing.verifying_key().to_encoded_point(false);
    let pub_bytes = pub_point.as_bytes();
    assert_eq!(pub_bytes.len(), 65);
    let x = &pub_bytes[1..33];
    let y = &pub_bytes[33..];

    let digest = [0x33u8; 32];
    let signature: Signature = signing.sign_prehash(&digest).unwrap();
    let sig_bytes = signature.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..];

    // Build verify command body matching stsafea_ecc_verify_signature.
    let build_verify_body = |digest: &[u8]| -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x00); // subject
        body.extend_from_slice(&NIST_P256_CURVE_ID);
        body.push(0x04); // point representation
        body.extend_from_slice(&(32u16).to_be_bytes());
        body.extend_from_slice(x);
        body.extend_from_slice(&(32u16).to_be_bytes());
        body.extend_from_slice(y);
        body.extend_from_slice(&(32u16).to_be_bytes());
        body.extend_from_slice(r);
        body.extend_from_slice(&(32u16).to_be_bytes());
        body.extend_from_slice(s);
        body.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        body.extend_from_slice(digest);
        body
    };

    let cmd = build_command(0x17, &build_verify_body(&digest));
    let (st, body) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    assert_eq!(body, vec![0x01]);

    // Same flow but with a different digest -- should report invalid.
    let cmd = build_command(0x17, &build_verify_body(&[0x99u8; 32]));
    let (st, body) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    assert_eq!(body, vec![0x00]);
}

#[test]
fn establish_key_matches_independent_ecdh() {
    let mut store = Store::fresh();
    let mut session = Session::new();

    // Provision slot 1 via Generate Key Pair so the simulator knows its
    // private key, then run an off-device ECDH against the public key it
    // returned, and confirm Establish Key reproduces the same shared secret.
    let slot = 1u8;
    let mut body = Vec::new();
    body.push(0x13);
    body.push(slot);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 2]);
    body.extend_from_slice(&NIST_P256_CURVE_ID);
    let cmd = build_command(0x11, &body);
    let (_, key_body) = round_trip(&mut store, &mut session, &cmd);
    let device_x = &key_body[3..35];
    let device_y = &key_body[37..69];
    let mut device_pub_bytes = [0u8; 65];
    device_pub_bytes[0] = 0x04;
    device_pub_bytes[1..33].copy_from_slice(device_x);
    device_pub_bytes[33..].copy_from_slice(device_y);
    let device_pub = p256::PublicKey::from_sec1_bytes(&device_pub_bytes).unwrap();

    // Off-device peer keypair
    let peer_secret = SecretKey::random(&mut OsRng);
    let peer_pub = peer_secret.public_key();
    let peer_point = peer_pub.to_encoded_point(false);
    let peer_pub_bytes = peer_point.as_bytes();
    let peer_x = &peer_pub_bytes[1..33];
    let peer_y = &peer_pub_bytes[33..];

    // Build Establish Key command:
    // [private_slot 1B][point_repr 1B][X_len 2B][X 32B][Y_len 2B][Y 32B]
    let mut body = Vec::new();
    body.push(slot);
    body.push(0x04);
    body.extend_from_slice(&(32u16).to_be_bytes());
    body.extend_from_slice(peer_x);
    body.extend_from_slice(&(32u16).to_be_bytes());
    body.extend_from_slice(peer_y);
    let cmd = build_command(0x18, &body);
    let (st, body) = round_trip(&mut store, &mut session, &cmd);
    assert_eq!(st, status::OK);
    assert_eq!(body.len(), 2 + 32);
    let device_secret = &body[2..];

    // Independent ECDH using peer_secret * device_pub.
    let independent =
        p256::ecdh::diffie_hellman(peer_secret.to_nonzero_scalar(), device_pub.as_affine());
    let independent_bytes: &[u8] = &independent.raw_secret_bytes();
    assert_eq!(independent_bytes, device_secret);
}

#[test]
fn frame_too_short_yields_length_error() {
    let mut store = Store::fresh();
    let mut session = Session::new();
    // Build a 2-byte "frame" that fails the >=3 check before CRC parsing.
    let raw = [0x02u8, 0x00];
    let resp = dispatch(&mut store, &mut session, &raw);
    let (st, _) = (resp[0] & 0x1F, ());
    assert_eq!(st, status::LENGTH_ERROR);
}

#[test]
fn parser_accepts_minimum_frame() {
    // A 1-byte command body + 2-byte CRC = 3 bytes is the minimum.
    let frame = build_command(0x02, &[]);
    let cmd = parse_command(&frame).unwrap_or_else(|e| panic!("parse failed: {e:?}"));
    assert_eq!(cmd.header, 0x02);
    assert_eq!(cmd.body.len(), 0);
}

#[test]
fn build_response_layout_matches_protocol() {
    // Response wire format: [hdr 1B][len 2B BE][body NB][crc 2B BE]
    // length = body.len() + 2 (CRC bytes, not the length field itself).
    let body = [1u8, 2, 3, 4, 5];
    let resp = build_response(status::OK, &body);
    assert_eq!(resp.len(), 1 + 2 + body.len() + 2);
    assert_eq!(resp[0] & 0x1F, status::OK);
    let length = u16::from_be_bytes([resp[1], resp[2]]);
    assert_eq!(length as usize, body.len() + 2);
    assert_eq!(&resp[3..3 + body.len()], &body);
    // CRC scope is [hdr][body] -- it does not include the length field.
    let mut crc_input = Vec::new();
    crc_input.push(resp[0]);
    crc_input.extend_from_slice(&body);
    let expected = crc16_x25(&crc_input);
    let actual = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    assert_eq!(actual, expected);
}
