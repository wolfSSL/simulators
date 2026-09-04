/* aes.rs
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

/// AES key management and cipher operations.
///
/// The cipher mode byte (Tag2 on one-shots, CreateCryptoObject subtype
/// for the multi-step flow) is honored: AES_CBC_NOPAD (0x0D),
/// AES_ECB_NOPAD (0x0E) and AES_CTR (0xF0) are implemented and
/// bench-verified against NIST SP800-38A vectors on SE050C applet
/// 3.1.1 and SE051 applet 7.2.0 (August 2026). Non-block-aligned
/// input to a NOPAD mode fails 0x6985 as on hardware. The padded CBC
/// variants (ISO9797, PKCS5) are not implemented.
///
/// Multi-step ciphering returns output incrementally: each
/// CipherUpdate emits the ciphertext/plaintext for the block-aligned
/// prefix it can process (bench-verified: 16 bytes in, 16 bytes out),
/// and CipherFinal emits only what remained.

use crate::apdu::*;
use crate::object_store::types::SecureObject;
use crate::object_store::{CryptoObjectState, ObjectStore};
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_4};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use rand::RngCore;

pub const CIPHER_MODE_CBC_NOPAD: u8 = 0x0D; // kSE05x_CipherMode_AES_CBC_NOPAD
pub const CIPHER_MODE_ECB_NOPAD: u8 = 0x0E; // kSE05x_CipherMode_AES_ECB_NOPAD
pub const CIPHER_MODE_CTR: u8 = 0xF0; // kSE05x_CipherMode_AES_CTR

/// AES block cipher over any of the three key sizes.
pub(crate) enum AnyAes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl AnyAes {
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => aes::Aes128::new_from_slice(key).ok().map(AnyAes::A128),
            24 => aes::Aes192::new_from_slice(key).ok().map(AnyAes::A192),
            32 => aes::Aes256::new_from_slice(key).ok().map(AnyAes::A256),
            _ => None,
        }
    }

    pub(crate) fn encrypt_block(&self, block: &mut [u8; 16]) {
        let ga = GenericArray::from_mut_slice(block);
        match self {
            AnyAes::A128(c) => c.encrypt_block(ga),
            AnyAes::A192(c) => c.encrypt_block(ga),
            AnyAes::A256(c) => c.encrypt_block(ga),
        }
    }

    pub(crate) fn decrypt_block(&self, block: &mut [u8; 16]) {
        let ga = GenericArray::from_mut_slice(block);
        match self {
            AnyAes::A128(c) => c.decrypt_block(ga),
            AnyAes::A192(c) => c.decrypt_block(ga),
            AnyAes::A256(c) => c.decrypt_block(ga),
        }
    }
}

/// Process block-aligned data in ECB mode.
fn ecb_process(cipher: &AnyAes, data: &[u8], encrypting: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        if encrypting {
            cipher.encrypt_block(&mut block);
        } else {
            cipher.decrypt_block(&mut block);
        }
        out.extend_from_slice(&block);
    }
    out
}

/// Process block-aligned data in CBC mode, advancing the chain vector.
pub(crate) fn cbc_process(cipher: &AnyAes, chain: &mut [u8; 16], data: &[u8], encrypting: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        if encrypting {
            for i in 0..16 {
                block[i] ^= chain[i];
            }
            cipher.encrypt_block(&mut block);
            chain.copy_from_slice(&block);
            out.extend_from_slice(&block);
        } else {
            let saved_ct = block;
            let mut pt = block;
            cipher.decrypt_block(&mut pt);
            for i in 0..16 {
                pt[i] ^= chain[i];
            }
            chain.copy_from_slice(&saved_ct);
            out.extend_from_slice(&pt);
        }
    }
    out
}

/// Process data (any length) in CTR mode, advancing the counter one
/// step per started block. Only the final chunk of a streaming
/// operation may be partial.
fn ctr_process(cipher: &AnyAes, counter: &mut [u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut keystream = *counter;
        cipher.encrypt_block(&mut keystream);
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ keystream[i]);
        }
        // Big-endian increment over the full 16-byte counter block.
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
    out
}

/// Apply a cipher mode to `data` in one pass. `chain` is the IV /
/// initial counter and is advanced in place. Returns Err(SW) on an
/// unsupported mode or misaligned NOPAD input.
fn apply_mode(
    mode: u8,
    key: &[u8],
    chain: &mut [u8; 16],
    data: &[u8],
    encrypting: bool,
    is_final: bool,
) -> Result<Vec<u8>, u16> {
    let cipher = AnyAes::new(key).ok_or(SW_CONDITIONS_NOT_SATISFIED)?;
    match mode {
        CIPHER_MODE_ECB_NOPAD => {
            if data.len() % 16 != 0 {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            }
            Ok(ecb_process(&cipher, data, encrypting))
        }
        CIPHER_MODE_CBC_NOPAD => {
            if data.len() % 16 != 0 {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            }
            Ok(cbc_process(&cipher, chain, data, encrypting))
        }
        CIPHER_MODE_CTR => {
            if !is_final && data.len() % 16 != 0 {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            }
            Ok(ctr_process(&cipher, chain, data))
        }
        _ => Err(SW_WRONG_DATA),
    }
}

/// Handle WRITE AES key command.
/// Tag1=obj_id(4B), Tag3=key_data (or Tag3=key_size for generation)
pub fn handle_write_aes_key(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };
    let creation_policy = match crate::policy::creation_policy(&tlvs) {
        Ok(policy) => policy,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };
    let object_existed = store.exists(&obj_id);
    if object_existed
        && !store.policy_allows(&obj_id, crate::policy::POLICY_OBJ_ALLOW_WRITE)
    {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Check if key data is provided in Tag3
    let key_data = tlv::find_tlv(&tlvs, TAG_3).map(|t| t.value.clone());

    // Check if this is key generation (P2=Generate) or has a key size tag
    let generated = apdu.p2 == P2_GENERATE
        || key_data.as_ref().is_some_and(|d| d.len() <= 2);
    let response = if generated {
        // Key generation: Tag3 contains 2-byte key size
        let key_len = key_data
            .as_ref()
            .filter(|d| d.len() == 2)
            .map(|d| ((d[0] as usize) << 8) | (d[1] as usize))
            .unwrap_or(16); // default to AES-128

        let key_len_bytes = match key_len {
            128 => 16,
            192 => 24,
            256 => 32,
            16 | 24 | 32 => key_len,
            _ => return ApduResponse::error(SW_WRONG_DATA),
        };

        let mut key = vec![0u8; key_len_bytes];
        rand::thread_rng().fill_bytes(&mut key);
        store.insert(obj_id, SecureObject::AESKey { key });
        ApduResponse::success()
    } else if let Some(key) = key_data {
        // Import key data
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return ApduResponse::error(SW_WRONG_DATA);
        }
        store.insert(obj_id, SecureObject::AESKey { key });
        ApduResponse::success()
    } else {
        ApduResponse::error(SW_WRONG_DATA)
    };
    if response.sw == SW_NO_ERROR && !object_existed {
        store.set_creation_metadata(
            obj_id,
            creation_policy,
            if generated { 0x02 } else { 0x01 },
        );
    }
    response
}

/// Handle WRITE HMAC key command (WriteSymmKey with P1=HMAC).
/// Policy(opt), Tag1=obj_id(4B), Tag3=key_data. HMAC keys have no fixed
/// length, so any non-empty Tag3 value is accepted as-is. An attached
/// policy is validated and recorded with the object (it is part of the
/// object's attributes on a real applet); note it cannot make the
/// object readable (see object_mgmt::handle_read).
pub fn handle_write_hmac_key(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // An empty policy TLV is not a valid HMAC derive-target policy on the
    // applet, even though other SDK wrappers use it to mean "not supplied".
    if tlv::find_tlv(&tlvs, crate::tlv::TAG_POLICY)
        .is_some_and(|tlv| tlv.value.is_empty())
    {
        return ApduResponse::error(SW_WRONG_DATA);
    }
    let creation_policy = match crate::policy::creation_policy(&tlvs) {
        Ok(policy) => policy,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };
    let policy = creation_policy
        .as_deref()
        .and_then(crate::policy::ar_header_union);
    let object_existed = store.exists(&obj_id);
    if object_existed
        && !store.policy_allows(&obj_id, crate::policy::POLICY_OBJ_ALLOW_WRITE)
    {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) if !t.value.is_empty() => {
            store.insert(obj_id, SecureObject::HMACKey { key: t.value.clone(), policy });
            if !object_existed {
                store.set_creation_metadata(obj_id, creation_policy, 0x01);
            }
            ApduResponse::success()
        }
        _ => ApduResponse::error(SW_WRONG_DATA),
    }
}

/// Shared body of the encrypt/decrypt one-shot handlers.
/// Tag1=key_id(4B), Tag2=cipher_mode(1B), Tag3=input, Tag4=IV(opt)
fn handle_cipher_oneshot(
    apdu: &ParsedApdu,
    store: &mut ObjectStore,
    encrypting: bool,
) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let cipher_mode = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let input = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => t.value.clone(),
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let mut chain = [0u8; 16];
    if let Some(t) = tlv::find_tlv(&tlvs, TAG_4) {
        if t.value.len() == 16 {
            chain.copy_from_slice(&t.value);
        } else if !t.value.is_empty() {
            return ApduResponse::error(SW_WRONG_DATA);
        }
    }

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let key_data = match &key_obj {
        SecureObject::AESKey { key } => key,
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    match apply_mode(cipher_mode, key_data, &mut chain, &input, encrypting, true) {
        Ok(out) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &out)]),
        Err(sw) => ApduResponse::error(sw),
    }
}

/// Handle AES Encrypt Oneshot.
/// INS=Crypto, P1=Cipher, P2=EncryptOneshot
pub fn handle_encrypt_oneshot(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    handle_cipher_oneshot(apdu, store, true)
}

/// Handle AES Decrypt Oneshot.
/// INS=Crypto, P1=Cipher, P2=DecryptOneshot
pub fn handle_decrypt_oneshot(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    handle_cipher_oneshot(apdu, store, false)
}

/// Handle CipherInit (encrypt or decrypt).
/// INS=Crypto, P1=Cipher, P2=EncryptInit(0x42)/DecryptInit(0x43)
/// Tag1=keyObjectID(4B), Tag2=cryptoObjectID(2B), Tag4=IV(opt)
///
/// The crypto object must have been created with CreateCryptoObject
/// (context CIPHER); its subtype selects the cipher mode. Init on a
/// never-created crypto object fails 0x6985, as bench-verified.
pub fn handle_cipher_init(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let encrypting = apdu.p2 == P2_ENCRYPT_INIT;
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let Some(&(context, subtype)) = store.crypto_object_types.get(&crypto_id) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    // kSE05x_CryptoContext_CIPHER
    if context != 0x02 {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    if !store.exists(&key_id) {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    let mut chain = vec![0u8; 16];
    if let Some(t) = tlv::find_tlv(&tlvs, TAG_4) {
        if t.value.len() == 16 {
            chain.copy_from_slice(&t.value);
        } else if !t.value.is_empty() {
            return ApduResponse::error(SW_WRONG_DATA);
        }
    }

    store.crypto_objects.insert(
        crypto_id,
        CryptoObjectState::Cipher {
            encrypting,
            mode: subtype,
            key_id,
            chain,
            pending: Vec::new(),
        },
    );

    ApduResponse::success()
}

/// Handle CipherUpdate.
/// INS=Crypto, P1=Cipher, P2=Update(0x0C)
/// Tag2=cryptoObjectID(2B), Tag3=inputData
///
/// Emits the output for every complete block available, holding back
/// only the sub-block remainder (bench-verified: each aligned update
/// returns its ciphertext immediately).
pub fn handle_cipher_update(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let input = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => t.value.clone(),
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let Some(CryptoObjectState::Cipher { encrypting, mode, key_id, chain, pending }) =
        store.crypto_objects.get(&crypto_id).cloned()
    else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let key = match store.get(&key_id) {
        Some(SecureObject::AESKey { key }) => key.clone(),
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let mut buffered = pending;
    buffered.extend_from_slice(&input);
    let aligned_len = buffered.len() - (buffered.len() % 16);
    let (aligned, rest) = buffered.split_at(aligned_len);

    let mut chain_arr = [0u8; 16];
    chain_arr.copy_from_slice(&chain);
    let output = match apply_mode(mode, &key, &mut chain_arr, aligned, encrypting, false) {
        Ok(out) => out,
        Err(sw) => return ApduResponse::error(sw),
    };

    let rest = rest.to_vec();
    store.crypto_objects.insert(
        crypto_id,
        CryptoObjectState::Cipher {
            encrypting,
            mode,
            key_id,
            chain: chain_arr.to_vec(),
            pending: rest,
        },
    );

    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &output)])
}

/// Handle CipherFinal.
/// INS=Crypto, P1=Cipher, P2=Final(0x0D)
/// Tag2=cryptoObjectID(2B), Tag3=remainingData(opt)
///
/// Processes what was still buffered plus the final chunk. NOPAD
/// modes require the total to be block-aligned (0x6985 otherwise);
/// a fully drained stream returns zero bytes, as on hardware.
pub fn handle_cipher_final(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let remaining = tlv::find_tlv(&tlvs, TAG_3).map(|t| t.value.clone());

    let state = match store.crypto_objects.remove(&crypto_id) {
        Some(s) => s,
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let CryptoObjectState::Cipher { encrypting, mode, key_id, chain, mut pending } = state else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    if let Some(rem) = remaining {
        pending.extend_from_slice(&rem);
    }

    let key = match store.get(&key_id) {
        Some(SecureObject::AESKey { key }) => key.clone(),
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let mut chain_arr = [0u8; 16];
    chain_arr.copy_from_slice(&chain);
    match apply_mode(mode, &key, &mut chain_arr, &pending, encrypting, true) {
        Ok(out) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &out)]),
        Err(sw) => ApduResponse::error(sw),
    }
}

#[cfg(test)]
mod cipher_mode_tests {
    use super::*;

    // NIST SP800-38A AES-128 vectors, bench-verified byte-for-byte on
    // SE050C applet 3.1.1 and SE051 applet 7.2.0.
    const KEY: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    ];
    const PT: [u8; 32] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
        0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    ];
    const CBC_IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];
    const CTR_IV: [u8; 16] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
    ];
    const ECB_CT: &str = "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf";
    const CBC_CT: &str = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2";
    const CTR_CT: &str = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff";

    const KEY_ID: [u8; 4] = [0, 0, 0, 0x50];

    fn store_with_key() -> ObjectStore {
        let mut store = ObjectStore::new();
        store.insert(KEY_ID, SecureObject::AESKey { key: KEY.to_vec() });
        store
    }

    fn oneshot_apdu(mode: u8, input: &[u8], iv: Option<&[u8]>, p2: u8) -> ParsedApdu {
        let mut data = vec![TAG_1, 0x04];
        data.extend_from_slice(&KEY_ID);
        data.extend_from_slice(&[TAG_2, 0x01, mode]);
        data.push(TAG_3);
        data.push(input.len() as u8);
        data.extend_from_slice(input);
        if let Some(iv) = iv {
            data.push(TAG_4);
            data.push(iv.len() as u8);
            data.extend_from_slice(iv);
        }
        ParsedApdu { cla: 0x80, ins: INS_CRYPTO, p1: P1_CIPHER, p2, data, le: None }
    }

    fn output_of(resp: &ApduResponse) -> Vec<u8> {
        assert_eq!(resp.sw, 0x9000, "SW {:04x}", resp.sw);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        tlv::find_tlv(&tlvs, TAG_1).unwrap().value.clone()
    }

    #[test]
    fn test_oneshot_modes_match_nist_vectors() {
        let mut store = store_with_key();
        let ecb = handle_encrypt_oneshot(
            &oneshot_apdu(CIPHER_MODE_ECB_NOPAD, &PT, None, P2_ENCRYPT_ONESHOT), &mut store);
        assert_eq!(hex::encode(output_of(&ecb)), ECB_CT);
        let cbc = handle_encrypt_oneshot(
            &oneshot_apdu(CIPHER_MODE_CBC_NOPAD, &PT, Some(&CBC_IV), P2_ENCRYPT_ONESHOT),
            &mut store);
        assert_eq!(hex::encode(output_of(&cbc)), CBC_CT);
        let ctr = handle_encrypt_oneshot(
            &oneshot_apdu(CIPHER_MODE_CTR, &PT, Some(&CTR_IV), P2_ENCRYPT_ONESHOT), &mut store);
        assert_eq!(hex::encode(output_of(&ctr)), CTR_CT);
    }

    #[test]
    fn test_oneshot_decrypt_round_trips() {
        let mut store = store_with_key();
        for (mode, iv) in [
            (CIPHER_MODE_ECB_NOPAD, None),
            (CIPHER_MODE_CBC_NOPAD, Some(&CBC_IV[..])),
            (CIPHER_MODE_CTR, Some(&CTR_IV[..])),
        ] {
            let enc = handle_encrypt_oneshot(
                &oneshot_apdu(mode, &PT, iv, P2_ENCRYPT_ONESHOT), &mut store);
            let ct = output_of(&enc);
            let dec = handle_decrypt_oneshot(
                &oneshot_apdu(mode, &ct, iv, P2_DECRYPT_ONESHOT), &mut store);
            assert_eq!(output_of(&dec), PT.to_vec(), "mode {:02x}", mode);
        }
    }

    #[test]
    fn test_oneshot_unaligned_nopad_fails_6985() {
        // Bench-verified: 20 bytes into CBC_NOPAD -> 0x6985.
        let mut store = store_with_key();
        let resp = handle_encrypt_oneshot(
            &oneshot_apdu(CIPHER_MODE_CBC_NOPAD, &PT[..20], Some(&CBC_IV), P2_ENCRYPT_ONESHOT),
            &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_oneshot_unknown_mode_fails() {
        let mut store = store_with_key();
        let resp = handle_encrypt_oneshot(
            &oneshot_apdu(0x18 /* AES_CBC_PKCS5, unimplemented */, &PT, None,
                P2_ENCRYPT_ONESHOT),
            &mut store);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn test_oneshot_missing_key_fails_6985() {
        // Bench-verified SW for operations on missing objects.
        let mut store = ObjectStore::new();
        let resp = handle_encrypt_oneshot(
            &oneshot_apdu(CIPHER_MODE_ECB_NOPAD, &PT, None, P2_ENCRYPT_ONESHOT), &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    fn init_apdu(crypto_id: u16, iv: Option<&[u8]>) -> ParsedApdu {
        let mut data = vec![TAG_1, 0x04];
        data.extend_from_slice(&KEY_ID);
        data.extend_from_slice(&[TAG_2, 0x02, (crypto_id >> 8) as u8, crypto_id as u8]);
        if let Some(iv) = iv {
            data.push(TAG_4);
            data.push(iv.len() as u8);
            data.extend_from_slice(iv);
        }
        ParsedApdu {
            cla: 0x80, ins: INS_CRYPTO, p1: P1_CIPHER, p2: P2_ENCRYPT_INIT, data, le: None,
        }
    }

    fn update_apdu(crypto_id: u16, input: &[u8]) -> ParsedApdu {
        let mut data = vec![TAG_2, 0x02, (crypto_id >> 8) as u8, crypto_id as u8];
        data.push(TAG_3);
        data.push(input.len() as u8);
        data.extend_from_slice(input);
        ParsedApdu { cla: 0x80, ins: INS_CRYPTO, p1: P1_CIPHER, p2: P2_UPDATE, data, le: None }
    }

    fn final_apdu(crypto_id: u16, input: &[u8]) -> ParsedApdu {
        let mut data = vec![TAG_2, 0x02, (crypto_id >> 8) as u8, crypto_id as u8];
        if !input.is_empty() {
            data.push(TAG_3);
            data.push(input.len() as u8);
            data.extend_from_slice(input);
        }
        ParsedApdu { cla: 0x80, ins: INS_CRYPTO, p1: P1_CIPHER, p2: P2_FINAL, data, le: None }
    }

    #[test]
    fn test_streaming_cbc_emits_output_per_update() {
        // Bench-verified: CipherUpdate(16B) returns the 16-byte
        // ciphertext block immediately, and Final(0B) returns nothing.
        let crypto_id = 0x0010u16;
        let mut store = store_with_key();
        store.crypto_object_types.insert(crypto_id, (0x02, CIPHER_MODE_CBC_NOPAD));

        assert_eq!(handle_cipher_init(&init_apdu(crypto_id, Some(&CBC_IV)), &mut store).sw,
                   0x9000);
        let u1 = handle_cipher_update(&update_apdu(crypto_id, &PT[..16]), &mut store);
        assert_eq!(hex::encode(output_of(&u1)), CBC_CT[..32]);
        let u2 = handle_cipher_update(&update_apdu(crypto_id, &PT[16..]), &mut store);
        assert_eq!(hex::encode(output_of(&u2)), CBC_CT[32..]);
        let f = handle_cipher_final(&final_apdu(crypto_id, &[]), &mut store);
        assert_eq!(output_of(&f).len(), 0);
    }

    #[test]
    fn test_streaming_init_without_created_crypto_object_fails() {
        // Bench-verified: 0x6985 on a never-created crypto object.
        let mut store = store_with_key();
        let resp = handle_cipher_init(&init_apdu(0x0777, Some(&CBC_IV)), &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
        let resp = handle_cipher_update(&update_apdu(0x0778, &PT[..16]), &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }
}

#[cfg(test)]
mod hmac_write_tests {
    use super::*;
    use crate::dispatch::dispatch;

    #[test]
    fn test_write_hmac_key_via_dispatch() {
        // WriteSymmKey with P1=HMAC and the transient INS bit set
        // (kSE05x_INS_WRITE | kSE05x_INS_TRANSIENT = 0x21), as sent by
        // sss_key_store_set_key for a kSSS_CipherType_HMAC object.
        let key = vec![0xA5u8; 32];
        let mut data = vec![TAG_1, 0x04, 0x00, 0x00, 0x00, 0x66];
        data.push(TAG_3);
        data.push(key.len() as u8);
        data.extend_from_slice(&key);

        let apdu = ParsedApdu {
            cla: 0x80,
            ins: 0x21,
            p1: P1_HMAC,
            p2: P2_DEFAULT,
            data,
            le: None,
        };
        let mut store = ObjectStore::new();
        let resp = dispatch(&apdu, &mut store, false);
        assert_eq!(resp.sw, 0x9000);
        match store.get(&[0x00, 0x00, 0x00, 0x66]) {
            Some(SecureObject::HMACKey { key: stored, policy }) => {
                assert_eq!(stored, &key);
                assert_eq!(*policy, None);
            }
            _ => panic!("HMACKey object not stored"),
        }
    }

    #[test]
    fn test_write_hmac_key_records_policy() {
        // WriteSymmKey with a leading policy TLV, as sent by
        // sss_key_store_set_key when an sss_policy_t is attached. One
        // entry: len=8, authId=0, AR header granting read.
        let key = vec![0x5Au8; 32];
        let header: u32 = crate::policy::POLICY_OBJ_ALLOW_READ | 0x0014_0000;
        let mut data = vec![crate::tlv::TAG_POLICY, 0x09, 0x08, 0x00, 0x00, 0x00, 0x00];
        data.extend_from_slice(&header.to_be_bytes());
        data.extend_from_slice(&[TAG_1, 0x04, 0x00, 0x00, 0x00, 0x67]);
        data.push(TAG_3);
        data.push(key.len() as u8);
        data.extend_from_slice(&key);

        let apdu = ParsedApdu {
            cla: 0x80,
            ins: 0x21,
            p1: P1_HMAC,
            p2: P2_DEFAULT,
            data,
            le: None,
        };
        let mut store = ObjectStore::new();
        let resp = dispatch(&apdu, &mut store, false);
        assert_eq!(resp.sw, 0x9000);
        match store.get(&[0x00, 0x00, 0x00, 0x67]) {
            Some(SecureObject::HMACKey { key: stored, policy }) => {
                assert_eq!(stored, &key);
                assert_eq!(*policy, Some(header));
            }
            _ => panic!("HMACKey object not stored"),
        }
    }

    #[test]
    fn test_write_hmac_key_malformed_policy_rejected() {
        // A policy TLV that does not parse as an entry sequence must fail
        // the write with SW_WRONG_DATA, not be recorded as "no policy".
        let key = vec![0xA5u8; 32];
        let mut data = vec![crate::tlv::TAG_POLICY, 0x03, 0xDE, 0xAD, 0xBE];
        data.extend_from_slice(&[TAG_1, 0x04, 0x00, 0x00, 0x00, 0x68]);
        data.push(TAG_3);
        data.push(key.len() as u8);
        data.extend_from_slice(&key);

        let apdu = ParsedApdu {
            cla: 0x80,
            ins: 0x21,
            p1: P1_HMAC,
            p2: P2_DEFAULT,
            data,
            le: None,
        };
        let mut store = ObjectStore::new();
        let resp = dispatch(&apdu, &mut store, false);
        assert_eq!(resp.sw, SW_WRONG_DATA);
        assert!(store.get(&[0x00, 0x00, 0x00, 0x68]).is_none());
    }

    #[test]
    fn test_write_hmac_key_empty_value_rejected() {
        let data = vec![TAG_1, 0x04, 0x00, 0x00, 0x00, 0x66, TAG_3, 0x00];
        let apdu = ParsedApdu {
            cla: 0x80,
            ins: 0x01,
            p1: P1_HMAC,
            p2: P2_DEFAULT,
            data,
            le: None,
        };
        let mut store = ObjectStore::new();
        let resp = dispatch(&apdu, &mut store, false);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }
}
