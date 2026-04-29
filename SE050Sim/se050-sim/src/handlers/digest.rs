/* digest.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

use crate::apdu::*;
use crate::object_store::{CryptoObjectState, ObjectStore};
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3};
use sha2::Digest;

fn compute_hash(mode: u8, data: &[u8]) -> Option<Vec<u8>> {
    match mode {
        0x01 => Some(sha1::Sha1::digest(data).to_vec()),
        0x07 => Some(sha2::Sha224::digest(data).to_vec()),
        0x04 => Some(sha2::Sha256::digest(data).to_vec()),
        0x05 => Some(sha2::Sha384::digest(data).to_vec()),
        0x06 => Some(sha2::Sha512::digest(data).to_vec()),
        _ => None,
    }
}

/// Handle Digest OneShot command.
/// INS=Crypto, P1=Default, P2=Oneshot
/// Tag1=digest_mode(1B), Tag2=data_to_hash
pub fn handle_digest_oneshot(apdu: &ParsedApdu, _store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let digest_mode = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let data = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    match compute_hash(digest_mode, data) {
        Some(hash) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &hash)]),
        None => ApduResponse::error(SW_WRONG_DATA),
    }
}

/// Handle DigestInit.
/// INS=Crypto, P1=Default, P2=Init(0x0B)
/// Tag1=digest_mode(1B), Tag2=cryptoObjectID(2B)
pub fn handle_digest_init(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let algo = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    store.crypto_objects.insert(
        crypto_id,
        CryptoObjectState::Digest {
            algo,
            data: Vec::new(),
        },
    );

    ApduResponse::success()
}

/// Handle DigestUpdate.
/// INS=Crypto, P1=Default, P2=Update(0x0C)
/// Tag2=cryptoObjectID(2B), Tag3=inputData
pub fn handle_digest_update(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let input = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    match store.crypto_objects.get_mut(&crypto_id) {
        Some(CryptoObjectState::Digest { data, .. }) => {
            data.extend_from_slice(input);
            ApduResponse::success()
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Handle DigestFinal.
/// INS=Crypto, P1=Default, P2=Final(0x0D)
/// Tag2=cryptoObjectID(2B), Tag3=remainingData(opt)
pub fn handle_digest_final(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Append any remaining data
    let remaining = tlv::find_tlv(&tlvs, TAG_3).map(|t| t.value.clone());

    let state = match store.crypto_objects.remove(&crypto_id) {
        Some(s) => s,
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    match state {
        CryptoObjectState::Digest { algo, mut data } => {
            if let Some(rem) = remaining {
                data.extend_from_slice(&rem);
            }
            match compute_hash(algo, &data) {
                Some(hash) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &hash)]),
                None => ApduResponse::error(SW_WRONG_DATA),
            }
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}
