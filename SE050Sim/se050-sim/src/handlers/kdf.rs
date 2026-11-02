/* kdf.rs
 *
 * Copyright (C) 2026 wolfSSL Inc. and Cardea Key contributors
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

//! HKDFExtractAndExpand (AN12543 4.15.1.1): RFC 5869 HKDF with an HMACKey
//! object as the input keying material, which never leaves the SE.
//!
//! TLV[TAG_1] IKM HMACKey id (policy: ALLOW_KDF), TAG_2 digest mode, TAG_3
//! salt (optional; empty = default salt of zeros), TAG_4 info (optional),
//! TAG_5 2-byte output length (1..768), TAG_7 optional target object (HMACKey
//! or AESKey of exactly that length) instead of returning the output.
//! TAG_6 (salt from an HMACKey) is not modelled and is refused with 0x6A80;
//! a TAG_7 that is not a 4-byte object ID is refused too.

use hmac::{Mac, SimpleHmac};

use crate::apdu::*;
use crate::object_store::types::SecureObject;
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_4, TAG_5};

pub const P2_HKDF: u8 = 0x2D;
pub const POLICY_OBJ_ALLOW_KDF: u32 = 0x0080_0000;
const TAG_7: u8 = 0x47;

fn hkdf<D>(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>>
where
    D: hmac::digest::Digest + hmac::digest::core_api::BlockSizeUser + Clone,
{
    let hash_len = <D as hmac::digest::Digest>::output_size();
    if len > 255 * hash_len {
        return None;
    }
    let zeros = vec![0u8; hash_len];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    let mut ext = <SimpleHmac<D> as hmac::digest::KeyInit>::new_from_slice(salt).ok()?;
    ext.update(ikm);
    let prk = ext.finalize().into_bytes();
    let mut out = Vec::with_capacity(len + hash_len);
    let mut t: Vec<u8> = Vec::new();
    let mut i: u8 = 1;
    while out.len() < len {
        let mut m = <SimpleHmac<D> as hmac::digest::KeyInit>::new_from_slice(&prk).ok()?;
        m.update(&t);
        m.update(info);
        m.update(&[i]);
        t = m.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        i = i.checked_add(1)?;
    }
    out.truncate(len);
    Some(out)
}

pub fn handle_hkdf(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let Ok(tlvs) = apdu.parse_tlvs() else {
        return ApduResponse::error(SW_WRONG_DATA);
    };
    let id: Option<[u8; 4]> = tlv::find_tlv(&tlvs, TAG_1).and_then(|t| t.value.as_slice().try_into().ok());
    let mode = tlv::find_tlv(&tlvs, TAG_2).and_then(|t| t.value.first().copied());
    let len = tlv::find_tlv(&tlvs, TAG_5)
        .filter(|t| t.value.len() == 2)
        .map(|t| u16::from_be_bytes([t.value[0], t.value[1]]) as usize);
    let (Some(id), Some(mode), Some(len)) = (id, mode, len) else {
        return ApduResponse::error(SW_WRONG_DATA);
    };
    if len == 0 || len > 768 {
        return ApduResponse::error(SW_WRONG_DATA);
    }
    // TAG_6 names an object holding the salt (Se05x_API_HKDF_Extended).
    // Not supported yet: refused rather than silently using the zero salt.
    if tlv::find_tlv(&tlvs, crate::tlv::TAG_6).is_some() {
        return ApduResponse::error(SW_WRONG_DATA);
    }
    // TAG_7 present = output into that object; it must be an object ID.
    let target: Option<[u8; 4]> = match tlv::find_tlv(&tlvs, TAG_7) {
        None => None,
        Some(t) => match <[u8; 4]>::try_from(t.value.as_slice()) {
            Ok(id) => Some(id),
            Err(_) => return ApduResponse::error(SW_WRONG_DATA),
        },
    };
    let salt = tlv::find_tlv(&tlvs, TAG_3).map(|t| t.value.clone()).unwrap_or_default();
    let info = tlv::find_tlv(&tlvs, TAG_4).map(|t| t.value.clone()).unwrap_or_default();
    let ikm = match store.get(&id) {
        Some(SecureObject::HMACKey { key, .. }) => key.clone(),
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };
    if !store.policy_allows(&id, POLICY_OBJ_ALLOW_KDF) {
        return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
    }
    let out = match mode {
        0x01 => hkdf::<sha1::Sha1>(&salt, &ikm, &info, len),
        0x04 => hkdf::<sha2::Sha256>(&salt, &ikm, &info, len),
        0x05 => hkdf::<sha2::Sha384>(&salt, &ikm, &info, len),
        0x06 => hkdf::<sha2::Sha512>(&salt, &ikm, &info, len),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };
    let Some(out) = out else {
        return ApduResponse::error(SW_WRONG_DATA);
    };
    if let Some(target) = target {
        // Output into an existing object of exactly the requested length.
        let fits = match store.get(&target) {
            Some(SecureObject::HMACKey { key, .. }) | Some(SecureObject::AESKey { key }) => key.len() == len,
            _ => false,
        };
        if !fits || !store.policy_allows(&target, crate::policy::POLICY_OBJ_ALLOW_WRITE) {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        }
        match store.get_mut(&target) {
            Some(SecureObject::HMACKey { key, .. }) | Some(SecureObject::AESKey { key }) => *key = out,
            _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
        }
        store.touch();
        return ApduResponse::success();
    }
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &out)])
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 test case 1 (SHA-256)
    #[test]
    fn rfc5869_case1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf::<sha2::Sha256>(&salt, &ikm, &info, 42).unwrap();
        assert_eq!(hex::encode(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    #[test]
    fn hkdf_apdu_with_policy() {
        let mut store = ObjectStore::new();
        let id = [0x7D, 0xA0, 0x00, 0x20];
        store.insert(id, SecureObject::HMACKey { key: vec![0x0b; 22], policy: None });
        let mut pol = vec![8u8];
        pol.extend_from_slice(&[0; 4]);
        pol.extend_from_slice(&POLICY_OBJ_ALLOW_KDF.to_be_bytes());
        store.set_creation_metadata(id, Some(pol), 0x01);
        let mut data = Tlv::new(TAG_1, &id).encode();
        data.extend(Tlv::new(TAG_2, &[0x04]).encode());
        data.extend(Tlv::new(TAG_3, &(0x00..=0x0c).collect::<Vec<u8>>()).encode());
        data.extend(Tlv::new(TAG_4, &(0xf0..=0xf9).collect::<Vec<u8>>()).encode());
        data.extend(Tlv::new(TAG_5, &[0x00, 42]).encode());
        let mut raw = vec![0x80, INS_CRYPTO, 0x00, P2_HKDF, data.len() as u8];
        raw.extend(data);
        let r = handle_hkdf(&ParsedApdu::parse(&raw).unwrap(), &mut store);
        assert_eq!(r.sw, SW_NO_ERROR);
        let t = crate::tlv::parse_tlvs(&r.data).unwrap();
        assert_eq!(hex::encode(&t[0].value), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        // a key whose policy lacks ALLOW_KDF is refused
        let id2 = [0x7D, 0xA0, 0x00, 0x21];
        store.insert(id2, SecureObject::HMACKey { key: vec![1; 32], policy: None });
        let mut pol = vec![8u8];
        pol.extend_from_slice(&[0; 4]);
        pol.extend_from_slice(&0x1000_0000u32.to_be_bytes());
        store.set_creation_metadata(id2, Some(pol), 0x01);
        raw[5 + 2..5 + 6].copy_from_slice(&id2);
        assert_eq!(handle_hkdf(&ParsedApdu::parse(&raw).unwrap(), &mut store).sw, SW_COMMAND_NOT_ALLOWED);
    }

    #[test]
    fn hkdf_refuses_salt_object_and_malformed_target() {
        let mut store = ObjectStore::new();
        let id = [0x7D, 0xA0, 0x00, 0x20];
        store.insert(id, SecureObject::HMACKey { key: vec![0x0b; 22], policy: None });
        let mut base = |extra: &[u8]| {
            let mut data = Tlv::new(TAG_1, &id).encode();
            data.extend(Tlv::new(TAG_2, &[0x04]).encode());
            data.extend(Tlv::new(TAG_5, &[0x00, 32]).encode());
            data.extend_from_slice(extra);
            let mut raw = vec![0x80, INS_CRYPTO, 0x00, P2_HKDF, data.len() as u8];
            raw.extend(data);
            handle_hkdf(&ParsedApdu::parse(&raw).unwrap(), &mut store)
        };
        // salt from an object (TAG_6): not supported, refused
        assert_eq!(base(&Tlv::new(crate::tlv::TAG_6, &[0x7D, 0xA0, 0x00, 0x30]).encode()).sw, SW_WRONG_DATA);
        // TAG_7 that is not an object ID: refused, nothing returned
        let r = base(&Tlv::new(TAG_7, &[0x7D, 0xA0, 0x00]).encode());
        assert_eq!(r.sw, SW_WRONG_DATA);
        assert!(r.data.is_empty());
        // without either, the key comes back
        assert_eq!(base(&[]).sw, SW_NO_ERROR);
    }
}
