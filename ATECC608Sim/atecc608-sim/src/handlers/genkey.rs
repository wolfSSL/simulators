/* genkey.rs
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
use crate::object_store::{Device, NUM_SLOTS};
use crate::session::Session;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;

/// GenKey command (opcode 0x40).
///
/// P1 mode:
///   0x04 = Private key generation (store new P-256 key in the slot, return pubkey).
///   0x00 = Public key derivation (compute pubkey from an already-stored private, no write).
///   0x10 = Digest (variants we don't implement).
///
/// P2 = key ID (slot number, 0..15 for ECC slots).
/// Response = 64-byte uncompressed public key (X||Y), NO 0x04 SEC1 prefix.
pub fn handle(device: &mut Device, _session: &mut Session, cmd: &Command) -> Vec<u8> {
    let slot = cmd.p2 as usize;
    if slot >= NUM_SLOTS {
        return atca::status_response(status::PARSE_ERROR);
    }
    match cmd.p1 {
        0x04 => {
            if device.slot_locked(slot) {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            let sk = SigningKey::random(&mut OsRng);
            let priv_scalar = sk.to_bytes();
            let pk_bytes = pubkey_raw(&sk);
            // Store the 32-byte scalar in slot bytes [0..32].
            let slot_data = &mut device.slots[slot].data;
            if slot_data.len() < 32 {
                slot_data.resize(32, 0);
            }
            slot_data[..32].copy_from_slice(&priv_scalar);
            atca::build_response(&pk_bytes)
        }
        0x00 => {
            // Derive public key from stored scalar.
            let scalar = match slot_scalar(device, slot) {
                Some(s) => s,
                None => return atca::status_response(status::EXECUTION_ERROR),
            };
            let sk = match SigningKey::from_bytes(&scalar.into()) {
                Ok(k) => k,
                Err(_) => return atca::status_response(status::EXECUTION_ERROR),
            };
            atca::build_response(&pubkey_raw(&sk))
        }
        _ => atca::status_response(status::PARSE_ERROR),
    }
}

pub fn pubkey_raw(sk: &SigningKey) -> [u8; 64] {
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    // Encoded point format: 0x04 || X(32) || Y(32). ATECC returns X||Y only.
    let bytes = point.as_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[1..65]);
    out
}

pub fn slot_scalar(device: &Device, slot: usize) -> Option<[u8; 32]> {
    let data = &device.slots[slot].data;
    if data.len() < 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[..32]);
    Some(out)
}
