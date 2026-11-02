/* mac.rs
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

/// MAC operations (HMAC + AES-CMAC), one-shot and multi-step.
///
/// Bench-verified against SE050C applet 3.1.1 and SE051 applet 7.2.0
/// (August 2026): MACOneShot generate returns the exact RFC 4231
/// HMAC-SHA256 and NIST SP800-38B CMAC-AES-128 vectors. HMAC algos
/// operate on HMACKey objects, CMAC on AESKey objects.
///
/// Wire format (Plug & Trust v04.07.01):
/// * One-shot: INS_CRYPTO, P1_MAC, P2 = GenerateOneshot(0x45) /
///   ValidateOneshot(0x46). Tag1=keyID(4B), Tag2=algo(1B),
///   Tag3=data(opt), Tag5=MAC to validate (validate only).
///   Response Tag1 = MAC (generate) or result byte (validate).
/// * Multi-step: MACInit is P2 = Generate(0x03) / Validate(0x44) with
///   Tag1=keyID, Tag2=cryptoObjectID(2B); MACUpdate/MACFinal carry the
///   data in Tag1 and the crypto object ID in Tag2 (unlike digest and
///   cipher, which use Tag3/Tag2). The crypto object must have been
///   created with CreateCryptoObject first (ops on a never-created
///   object fail 0x6985 on real applets).

use crate::apdu::*;
use crate::object_store::types::SecureObject;
use crate::object_store::{CryptoObjectState, ObjectStore};
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_5};

use cmac::Cmac;
use hmac::{Mac, SimpleHmac};

// kSE05x_MACAlgo values.
const MAC_HMAC_SHA1: u8 = 0x18;
const MAC_HMAC_SHA256: u8 = 0x19;
const MAC_HMAC_SHA384: u8 = 0x1A;
const MAC_HMAC_SHA512: u8 = 0x1B;
const MAC_CMAC_AES: u8 = 0x31;

fn hmac_compute<D>(key: &[u8], data: &[u8]) -> Vec<u8>
where
    D: hmac::digest::Digest + hmac::digest::core_api::BlockSizeUser,
{
    let mut mac = <SimpleHmac<D> as hmac::digest::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn cmac_aes(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    // A macro sidesteps the deep trait bounds Cmac<C> would need in a
    // generic helper; the three AES key sizes are concrete here.
    macro_rules! do_cmac {
        ($cipher:ty) => {{
            let mut mac = <Cmac<$cipher> as cmac::digest::KeyInit>::new_from_slice(key).ok()?;
            Mac::update(&mut mac, data);
            Some(mac.finalize().into_bytes().to_vec())
        }};
    }
    match key.len() {
        16 => do_cmac!(aes::Aes128),
        24 => do_cmac!(aes::Aes192),
        32 => do_cmac!(aes::Aes256),
        _ => None,
    }
}

/// Compute a MAC. Returns Err(SW) when the algo/key-object pairing is
/// invalid: HMAC algos need an HMACKey, CMAC needs an AESKey.
fn compute_mac(algo: u8, key_obj: &SecureObject, data: &[u8]) -> Result<Vec<u8>, u16> {
    match algo {
        MAC_HMAC_SHA1 | MAC_HMAC_SHA256 | MAC_HMAC_SHA384 | MAC_HMAC_SHA512 => {
            let SecureObject::HMACKey { key, .. } = key_obj else {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            };
            Ok(match algo {
                MAC_HMAC_SHA1 => hmac_compute::<sha1::Sha1>(key, data),
                MAC_HMAC_SHA256 => hmac_compute::<sha2::Sha256>(key, data),
                MAC_HMAC_SHA384 => hmac_compute::<sha2::Sha384>(key, data),
                _ => hmac_compute::<sha2::Sha512>(key, data),
            })
        }
        MAC_CMAC_AES => {
            let SecureObject::AESKey { key } = key_obj else {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            };
            cmac_aes(key, data).ok_or(SW_CONDITIONS_NOT_SATISFIED)
        }
        _ => Err(SW_WRONG_DATA),
    }
}

fn mac_response(mac: Vec<u8>, expected: Option<&[u8]>) -> ApduResponse {
    match expected {
        None => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &mac)]),
        Some(exp) => {
            let result = if exp == mac.as_slice() { 0x01 } else { 0x02 };
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[result])])
        }
    }
}

/// MACOneShot (generate or validate).
pub fn handle_oneshot(apdu: &ParsedApdu, store: &mut ObjectStore, validate: bool) -> ApduResponse {
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
    let algo = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };
    let data = tlv::find_tlv(&tlvs, TAG_3)
        .map(|t| t.value.clone())
        .unwrap_or_default();
    let expected = if validate {
        match tlv::find_tlv(&tlvs, TAG_5) {
            Some(t) => Some(t.value.clone()),
            None => return ApduResponse::error(SW_WRONG_DATA),
        }
    } else {
        None
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };
    // Generating a MAC needs POLICY_OBJ_ALLOW_SIGN for the current session
    // owner; validating needs POLICY_OBJ_ALLOW_VERIFY (AN12543 policy table).
    let needed = if validate { crate::policy::POLICY_OBJ_ALLOW_VERIFY } else { crate::policy::POLICY_OBJ_ALLOW_SIGN };
    if !store.policy_allows(&key_id, needed) {
        return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
    }
    match compute_mac(algo, &key_obj, &data) {
        Ok(mac) => mac_response(mac, expected.as_deref()),
        Err(sw) => ApduResponse::error(sw),
    }
}

/// MACInit: Tag1=keyID(4B), Tag2=cryptoObjectID(2B). The MAC algo
/// comes from the crypto object's CreateCryptoObject subtype.
pub fn handle_init(apdu: &ParsedApdu, store: &mut ObjectStore, validate: bool) -> ApduResponse {
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
    // The crypto object must have been created first; ops on a
    // never-created crypto object fail 0x6985 on real applets. MAC
    // contexts are created with kSE05x_CryptoContext_SIGNATURE (0x03)
    // by the SDK; refuse digest/cipher objects like their handlers do.
    let Some(&(context, subtype)) = store.crypto_object_types.get(&crypto_id) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    if context != 0x03 {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    if !store.exists(&key_id) {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    store.crypto_objects.insert(
        crypto_id,
        CryptoObjectState::Mac {
            algo: subtype,
            validate,
            key_id,
            data: Vec::new(),
        },
    );
    ApduResponse::success()
}

/// MACUpdate: Tag1=data(opt), Tag2=cryptoObjectID.
pub fn handle_update(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };
    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };
    let input = tlv::find_tlv(&tlvs, TAG_1)
        .map(|t| t.value.clone())
        .unwrap_or_default();
    match store.crypto_objects.get_mut(&crypto_id) {
        Some(CryptoObjectState::Mac { data, .. }) => {
            data.extend_from_slice(&input);
            ApduResponse::success()
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// MACFinal: Tag1=data, Tag2=cryptoObjectID, Tag5=MAC to validate
/// (validate contexts). Response mirrors the one-shot forms.
pub fn handle_final(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };
    let crypto_id = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };
    let input = tlv::find_tlv(&tlvs, TAG_1)
        .map(|t| t.value.clone())
        .unwrap_or_default();
    let expected_tlv = tlv::find_tlv(&tlvs, TAG_5).map(|t| t.value.clone());

    let state = match store.crypto_objects.remove(&crypto_id) {
        Some(s) => s,
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };
    let CryptoObjectState::Mac { algo, validate, key_id, mut data } = state else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    data.extend_from_slice(&input);

    let expected = if validate {
        match expected_tlv {
            Some(v) => Some(v),
            None => return ApduResponse::error(SW_WRONG_DATA),
        }
    } else {
        None
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };
    // Generating a MAC needs POLICY_OBJ_ALLOW_SIGN for the current session
    // owner; validating needs POLICY_OBJ_ALLOW_VERIFY (AN12543 policy table).
    let needed = if validate { crate::policy::POLICY_OBJ_ALLOW_VERIFY } else { crate::policy::POLICY_OBJ_ALLOW_SIGN };
    if !store.policy_allows(&key_id, needed) {
        return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
    }
    match compute_mac(algo, &key_obj, &data) {
        Ok(mac) => mac_response(mac, expected.as_deref()),
        Err(sw) => ApduResponse::error(sw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 1.
    const HMAC_KEY: [u8; 20] = [0x0B; 20];
    const HMAC_MSG: &[u8] = b"Hi There";
    const HMAC_EXPECTED: &str =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    // NIST SP800-38B CMAC-AES128, 16-byte message.
    const CMAC_KEY: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    ];
    const CMAC_MSG: [u8; 16] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    ];
    const CMAC_EXPECTED: &str = "070a16b46b4d4144f79bdd9dd04a287c";

    fn oneshot_apdu(key_id: [u8; 4], algo: u8, data: &[u8], p2: u8) -> ParsedApdu {
        let mut body = vec![TAG_1, 0x04];
        body.extend_from_slice(&key_id);
        body.extend_from_slice(&[TAG_2, 0x01, algo]);
        body.push(TAG_3);
        body.push(data.len() as u8);
        body.extend_from_slice(data);
        ParsedApdu {
            cla: 0x80,
            ins: INS_CRYPTO,
            p1: P1_MAC,
            p2,
            data: body,
            le: None,
        }
    }

    #[test]
    fn test_hmac_sha256_oneshot_rfc4231_vector() {
        // Chip output bench-verified on applet 3.1.1 and 7.2.0.
        let key_id = [0, 0, 0, 0x70];
        let mut store = ObjectStore::new();
        store.insert(key_id, SecureObject::HMACKey { key: HMAC_KEY.to_vec(), policy: None });
        let resp = handle_oneshot(
            &oneshot_apdu(key_id, MAC_HMAC_SHA256, HMAC_MSG, P2_GENERATE_ONESHOT),
            &mut store, false);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(hex::encode(&tlv::find_tlv(&tlvs, TAG_1).unwrap().value), HMAC_EXPECTED);
    }

    #[test]
    fn test_cmac_aes128_oneshot_nist_vector() {
        let key_id = [0, 0, 0, 0x71];
        let mut store = ObjectStore::new();
        store.insert(key_id, SecureObject::AESKey { key: CMAC_KEY.to_vec() });
        let resp = handle_oneshot(
            &oneshot_apdu(key_id, MAC_CMAC_AES, &CMAC_MSG, P2_GENERATE_ONESHOT),
            &mut store, false);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(hex::encode(&tlv::find_tlv(&tlvs, TAG_1).unwrap().value), CMAC_EXPECTED);
    }

    #[test]
    fn test_validate_oneshot_result_bytes() {
        let key_id = [0, 0, 0, 0x72];
        let mut store = ObjectStore::new();
        store.insert(key_id, SecureObject::HMACKey { key: HMAC_KEY.to_vec(), policy: None });
        let good = hex::decode(HMAC_EXPECTED).unwrap();

        let mut apdu = oneshot_apdu(key_id, MAC_HMAC_SHA256, HMAC_MSG, P2_VALIDATE_ONESHOT);
        apdu.data.push(TAG_5);
        apdu.data.push(good.len() as u8);
        apdu.data.extend_from_slice(&good);
        let resp = handle_oneshot(&apdu, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, [0x01]);

        let mut bad = good.clone();
        bad[0] ^= 1;
        let mut apdu = oneshot_apdu(key_id, MAC_HMAC_SHA256, HMAC_MSG, P2_VALIDATE_ONESHOT);
        apdu.data.push(TAG_5);
        apdu.data.push(bad.len() as u8);
        apdu.data.extend_from_slice(&bad);
        let resp = handle_oneshot(&apdu, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, [0x02]);
    }

    #[test]
    fn test_mac_wrong_key_object_type_fails() {
        // HMAC algos need an HMACKey; CMAC needs an AESKey.
        let key_id = [0, 0, 0, 0x73];
        let mut store = ObjectStore::new();
        store.insert(key_id, SecureObject::AESKey { key: CMAC_KEY.to_vec() });
        let resp = handle_oneshot(
            &oneshot_apdu(key_id, MAC_HMAC_SHA256, HMAC_MSG, P2_GENERATE_ONESHOT),
            &mut store, false);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_mac_streaming_matches_oneshot() {
        let key_id = [0, 0, 0, 0x74];
        let crypto_id = 0x0030u16;
        let mut store = ObjectStore::new();
        store.insert(key_id, SecureObject::HMACKey { key: HMAC_KEY.to_vec(), policy: None });
        store.crypto_object_types.insert(crypto_id, (0x03, MAC_HMAC_SHA256));

        let mut body = vec![TAG_1, 0x04];
        body.extend_from_slice(&key_id);
        body.extend_from_slice(&[TAG_2, 0x02, 0x00, 0x30]);
        let init = ParsedApdu {
            cla: 0x80, ins: INS_CRYPTO, p1: P1_MAC, p2: P2_GENERATE, data: body, le: None,
        };
        assert_eq!(handle_init(&init, &mut store, false).sw, 0x9000);

        let update = ParsedApdu {
            cla: 0x80, ins: INS_CRYPTO, p1: P1_MAC, p2: P2_UPDATE,
            data: vec![TAG_1, 0x02, b'H', b'i', TAG_2, 0x02, 0x00, 0x30],
            le: None,
        };
        assert_eq!(handle_update(&update, &mut store).sw, 0x9000);

        let fin = ParsedApdu {
            cla: 0x80, ins: INS_CRYPTO, p1: P1_MAC, p2: P2_FINAL,
            data: vec![TAG_1, 0x06, b' ', b'T', b'h', b'e', b'r', b'e',
                       TAG_2, 0x02, 0x00, 0x30],
            le: None,
        };
        let resp = handle_final(&fin, &mut store);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(hex::encode(&tlv::find_tlv(&tlvs, TAG_1).unwrap().value), HMAC_EXPECTED);
    }

    #[test]
    fn test_mac_init_without_created_crypto_object_fails() {
        // Bench-verified pattern: ops on a never-created crypto object
        // fail 0x6985.
        let key_id = [0, 0, 0, 0x75];
        let mut store = ObjectStore::new();
        store.insert(key_id, SecureObject::HMACKey { key: HMAC_KEY.to_vec(), policy: None });
        let mut body = vec![TAG_1, 0x04];
        body.extend_from_slice(&key_id);
        body.extend_from_slice(&[TAG_2, 0x02, 0x07, 0x77]);
        let init = ParsedApdu {
            cla: 0x80, ins: INS_CRYPTO, p1: P1_MAC, p2: P2_GENERATE, data: body, le: None,
        };
        assert_eq!(handle_init(&init, &mut store, false).sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_mac_init_rejects_non_signature_context_object() {
        // A crypto object created with the DIGEST context (0x01) must
        // not be usable as a MAC context; the SDK creates MAC contexts
        // with kSE05x_CryptoContext_SIGNATURE (0x03).
        let key_id = [0, 0, 0, 0x76];
        let crypto_id = 0x0031u16;
        let mut store = ObjectStore::new();
        store.insert(key_id, SecureObject::HMACKey { key: HMAC_KEY.to_vec(), policy: None });
        store.crypto_object_types.insert(crypto_id, (0x01, 0x04)); // DIGEST/SHA256
        let mut body = vec![TAG_1, 0x04];
        body.extend_from_slice(&key_id);
        body.extend_from_slice(&[TAG_2, 0x02, 0x00, 0x31]);
        let init = ParsedApdu {
            cla: 0x80, ins: INS_CRYPTO, p1: P1_MAC, p2: P2_GENERATE, data: body, le: None,
        };
        assert_eq!(handle_init(&init, &mut store, false).sw, SW_CONDITIONS_NOT_SATISFIED);
    }
}
