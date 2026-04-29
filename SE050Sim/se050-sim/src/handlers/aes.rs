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

use crate::apdu::*;
use crate::object_store::types::SecureObject;
use crate::object_store::{CryptoObjectState, ObjectStore};
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_4};

use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use rand::RngCore;

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

    // Check if key data is provided in Tag3
    let key_data = tlv::find_tlv(&tlvs, TAG_3).map(|t| t.value.clone());

    // Check if this is key generation (P2=Generate) or has a key size tag
    if apdu.p2 == P2_GENERATE || key_data.as_ref().map_or(false, |d| d.len() <= 2) {
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
    }
}

/// Handle AES Encrypt Oneshot.
/// INS=Crypto, P1=Cipher, P2=EncryptOneshot
/// Tag1=key_id(4B), Tag2=cipher_mode(1B), Tag3=plaintext, Tag4=IV(opt)
pub fn handle_encrypt_oneshot(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    let _cipher_mode = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let plaintext = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => t.value.clone(),
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let iv = tlv::find_tlv(&tlvs, TAG_4)
        .map(|t| t.value.clone())
        .unwrap_or_else(|| vec![0u8; 16]); // Zero IV if not provided

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let key_data = match &key_obj {
        SecureObject::AESKey { key } => key,
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    // AES-CBC encryption
    let ciphertext = match key_data.len() {
        16 => aes_cbc_encrypt::<aes::Aes128>(key_data, &iv, &plaintext),
        24 => aes_cbc_encrypt::<aes::Aes192>(key_data, &iv, &plaintext),
        32 => aes_cbc_encrypt::<aes::Aes256>(key_data, &iv, &plaintext),
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    match ciphertext {
        Some(ct) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &ct)]),
        None => ApduResponse::error(SW_WRONG_DATA),
    }
}

/// Handle AES Decrypt Oneshot.
/// INS=Crypto, P1=Cipher, P2=DecryptOneshot
/// Tag1=key_id(4B), Tag2=cipher_mode(1B), Tag3=ciphertext, Tag4=IV(opt)
pub fn handle_decrypt_oneshot(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    let _cipher_mode = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let ciphertext = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => t.value.clone(),
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let iv = tlv::find_tlv(&tlvs, TAG_4)
        .map(|t| t.value.clone())
        .unwrap_or_else(|| vec![0u8; 16]);

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let key_data = match &key_obj {
        SecureObject::AESKey { key } => key,
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let plaintext = match key_data.len() {
        16 => aes_cbc_decrypt::<aes::Aes128>(key_data, &iv, &ciphertext),
        24 => aes_cbc_decrypt::<aes::Aes192>(key_data, &iv, &ciphertext),
        32 => aes_cbc_decrypt::<aes::Aes256>(key_data, &iv, &ciphertext),
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    match plaintext {
        Some(pt) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &pt)]),
        None => ApduResponse::error(SW_WRONG_DATA),
    }
}

/// Handle CipherInit (encrypt or decrypt).
/// INS=Crypto, P1=Cipher, P2=EncryptInit(0x42)/DecryptInit(0x43)
/// Tag1=keyObjectID(4B), Tag2=cryptoObjectID(2B), Tag4=IV(opt)
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

    let iv = tlv::find_tlv(&tlvs, TAG_4)
        .map(|t| t.value.clone())
        .unwrap_or_else(|| vec![0u8; 16]);

    store.crypto_objects.insert(
        crypto_id,
        CryptoObjectState::Cipher {
            encrypting,
            key_id,
            iv,
            accumulated: Vec::new(),
        },
    );

    ApduResponse::success()
}

/// Handle CipherUpdate.
/// INS=Crypto, P1=Cipher, P2=Update(0x0C)
/// Tag2=cryptoObjectID(2B), Tag3=inputData
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

    // Accumulate data - process in final
    match store.crypto_objects.get_mut(&crypto_id) {
        Some(CryptoObjectState::Cipher { accumulated, .. }) => {
            accumulated.extend_from_slice(&input);
            // For streaming cipher, we could process block-aligned chunks here.
            // For simplicity, accumulate all and process in final.
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[])])
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Handle CipherFinal.
/// INS=Crypto, P1=Cipher, P2=Final(0x0D)
/// Tag2=cryptoObjectID(2B), Tag3=remainingData(opt)
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

    match state {
        CryptoObjectState::Cipher {
            encrypting,
            key_id,
            iv,
            mut accumulated,
        } => {
            if let Some(rem) = remaining {
                accumulated.extend_from_slice(&rem);
            }

            let key_obj = match store.get(&key_id) {
                Some(obj) => obj.clone(),
                None => return ApduResponse::error(SW_FILE_NOT_FOUND),
            };

            let key_data = match &key_obj {
                SecureObject::AESKey { key } => key,
                _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
            };

            let result = if encrypting {
                match key_data.len() {
                    16 => aes_cbc_encrypt::<aes::Aes128>(key_data, &iv, &accumulated),
                    24 => aes_cbc_encrypt::<aes::Aes192>(key_data, &iv, &accumulated),
                    32 => aes_cbc_encrypt::<aes::Aes256>(key_data, &iv, &accumulated),
                    _ => None,
                }
            } else {
                match key_data.len() {
                    16 => aes_cbc_decrypt::<aes::Aes128>(key_data, &iv, &accumulated),
                    24 => aes_cbc_decrypt::<aes::Aes192>(key_data, &iv, &accumulated),
                    32 => aes_cbc_decrypt::<aes::Aes256>(key_data, &iv, &accumulated),
                    _ => None,
                }
            };

            match result {
                Some(output) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &output)]),
                None => ApduResponse::error(SW_WRONG_DATA),
            }
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// AES-CBC encrypt with no padding (manual CBC chaining).
pub fn aes_cbc_encrypt<C>(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Option<Vec<u8>>
where
    C: BlockEncrypt + KeyInit,
{
    if plaintext.len() % 16 != 0 || iv.len() < 16 {
        return None;
    }
    let cipher = C::new_from_slice(key).ok()?;
    let mut result = Vec::with_capacity(plaintext.len());
    let mut prev_block = [0u8; 16];
    prev_block.copy_from_slice(&iv[..16]);

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev_block[i];
        }
        let ga = GenericArray::from_mut_slice(&mut block);
        cipher.encrypt_block(ga);
        prev_block.copy_from_slice(&block);
        result.extend_from_slice(&block);
    }

    Some(result)
}

/// AES-CBC decrypt with no padding (manual CBC chaining).
fn aes_cbc_decrypt<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>>
where
    C: BlockDecrypt + KeyInit,
{
    if ciphertext.len() % 16 != 0 || iv.len() < 16 {
        return None;
    }
    let cipher = C::new_from_slice(key).ok()?;
    let mut result = Vec::with_capacity(ciphertext.len());
    let mut prev_block = [0u8; 16];
    prev_block.copy_from_slice(&iv[..16]);

    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let ga = GenericArray::from_mut_slice(&mut block);
        cipher.decrypt_block(ga);
        for i in 0..16 {
            block[i] ^= prev_block[i];
        }
        prev_block.copy_from_slice(chunk);
        result.extend_from_slice(&block);
    }

    Some(result)
}
