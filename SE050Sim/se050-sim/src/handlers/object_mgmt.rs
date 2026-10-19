/* object_mgmt.rs
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
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_4, TAG_POLICY};

/// Handle WRITE commands for Binary, UserID, and Counter objects.
pub fn handle_write(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    match apdu.cred_type() {
        P1_BINARY => handle_write_binary(apdu, store),
        // WriteUserID is refused in plain (unauthenticated) sessions:
        // bench-verified 0x6985 on SE050C applet 3.1.1 and SE051
        // applet 7.2.0 alike, via both the raw APDU and the sss layer.
        // The simulator only models plain sessions, so the write is
        // always refused.
        P1_USERID => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
        P1_COUNTER => handle_write_counter(apdu, store),
        _ => ApduResponse::error(SW_WRONG_P1P2),
    }
}

/// Handle READ commands for objects. ReadObject always refuses
/// symmetric key objects (HMACKey and AESKey), as every real applet
/// generation does regardless of any attached read policy (verified on
/// SE051 applet 7.2.0 and SE050C applet 3.1.1 hardware, including with
/// POLICY_OBJ_ALLOW_READ attached); size/list/type reads are
/// unaffected.
pub fn handle_read(apdu: &ParsedApdu, store: &mut ObjectStore, v7: bool) -> ApduResponse {
    match apdu.p2 {
        P2_DEFAULT => handle_read_object(apdu, store),
        P2_SIZE => handle_read_size(apdu, store),
        P2_LIST => handle_read_id_list(apdu, store, v7),
        P2_TYPE => handle_read_type(apdu, store, v7),
        P2_ATTRIBUTES => handle_read_attributes(apdu, store, v7),
        _ => ApduResponse::error(SW_WRONG_P1P2),
    }
}

/// Handle MGMT commands for object management.
pub fn handle_mgmt(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    match apdu.p2 {
        P2_EXIST => handle_check_exists(apdu, store),
        P2_DELETE_OBJECT => handle_delete(apdu, store),
        _ => ApduResponse::error(SW_WRONG_P1P2),
    }
}

fn extract_object_id(tlvs: &[Tlv]) -> Option<[u8; 4]> {
    let tag1 = tlv::find_tlv(tlvs, TAG_1)?;
    if tag1.value.len() != 4 {
        return None;
    }
    let mut id = [0u8; 4];
    id.copy_from_slice(&tag1.value);
    Some(id)
}

/// WriteBinary: Policy(opt), Tag1=objID, Tag2=offset(2B), Tag3=file
/// length(2B), Tag4=data. The file size is fixed at creation; writes
/// beyond it fail 0x6A80 and do not grow the file (bench-verified on
/// applet 3.1.1 and 7.2.0).
fn handle_write_binary(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let mut obj_id = None;
    let mut data = None;
    let mut offset: usize = 0;
    let mut file_len: Option<usize> = None;

    for tlv in &tlvs {
        match tlv.tag {
            TAG_POLICY => {}
            TAG_1 if obj_id.is_none() && tlv.value.len() == 4 => {
                let mut id = [0u8; 4];
                id.copy_from_slice(&tlv.value);
                obj_id = Some(id);
            }
            TAG_2 if tlv.value.len() == 2 => {
                offset = ((tlv.value[0] as usize) << 8) | (tlv.value[1] as usize);
            }
            TAG_3 if tlv.value.len() == 2 => {
                file_len = Some(((tlv.value[0] as usize) << 8) | (tlv.value[1] as usize));
            }
            TAG_4 => {
                data = Some(tlv.value.clone());
            }
            _ => {}
        }
    }

    let obj_id = match obj_id {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
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

    let write_data = data.unwrap_or_default();

    match store.get_mut(&obj_id) {
        Some(SecureObject::Binary { data: existing }) => {
            // Update in place; the file size is immutable.
            if offset + write_data.len() > existing.len() {
                return ApduResponse::error(SW_WRONG_DATA);
            }
            existing[offset..offset + write_data.len()].copy_from_slice(&write_data);
            let updated = SecureObject::Binary { data: existing.clone() };
            store.insert(obj_id, updated);
            ApduResponse::success()
        }
        Some(_) => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
        None => {
            // Create: the size comes from Tag3, defaulting to the data
            // length when absent.
            let size = file_len.unwrap_or(write_data.len());
            if offset + write_data.len() > size {
                return ApduResponse::error(SW_WRONG_DATA);
            }
            let mut full = vec![0u8; size];
            full[offset..offset + write_data.len()].copy_from_slice(&write_data);
            store.insert(obj_id, SecureObject::Binary { data: full });
            store.set_creation_metadata(obj_id, creation_policy, 0x01);
            ApduResponse::success()
        }
    }
}

/// WriteCounter serves three request shapes sharing one APDU header:
/// CreateCounter (Tag1 + Tag2=size), SetCounterValue (Tag1 +
/// Tag3=value bytes), and IncCounter (Tag1 only). Counter sizes are
/// fixed at creation; reads return exactly `size` bytes
/// (bench-verified with a 4-byte counter on applet 3.1.1 and 7.2.0).
fn handle_write_counter(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };
    let creation_policy = match crate::policy::creation_policy(&tlvs) {
        Ok(policy) => policy,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let size_tlv = tlv::find_tlv(&tlvs, TAG_2)
        .filter(|t| t.value.len() == 2)
        .map(|t| ((t.value[0] as u16) << 8) | (t.value[1] as u16));
    let value_tlv = tlv::find_tlv(&tlvs, TAG_3).map(|t| {
        let mut val = 0u64;
        for &b in &t.value {
            val = (val << 8) | (b as u64);
        }
        val
    });

    let existing = match store.get(&obj_id) {
        Some(SecureObject::Counter { value, size }) => Some((*value, *size)),
        Some(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
        None => None,
    };
    if existing.is_some()
        && !store.policy_allows(&obj_id, crate::policy::POLICY_OBJ_ALLOW_WRITE)
    {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    match (existing, size_tlv, value_tlv) {
        // CreateCounter (optionally with an initial value)
        (None, Some(size), value) => {
            if size == 0 || size > 8 {
                return ApduResponse::error(SW_WRONG_DATA);
            }
            store.insert(obj_id, SecureObject::Counter {
                value: value.unwrap_or(0),
                size,
            });
            store.set_creation_metadata(obj_id, creation_policy, 0x01);
            ApduResponse::success()
        }
        // SetCounterValue on an existing counter
        (Some((_, size)), _, Some(value)) => {
            store.insert(obj_id, SecureObject::Counter { value, size });
            ApduResponse::success()
        }
        // IncCounter
        (Some((value, size)), None, None) => {
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
            store.insert(obj_id, SecureObject::Counter {
                value: value.wrapping_add(1) & mask,
                size,
            });
            ApduResponse::success()
        }
        // Re-creating an existing counter or operating on a missing one
        (Some(_), Some(_), None) | (None, _, _) => {
            ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED)
        }
    }
}

fn handle_read_object(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };
    if !store.policy_allows(&obj_id, crate::policy::POLICY_OBJ_ALLOW_READ) {
        return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
    }

    // Optional offset from Tag2 and length from Tag3
    let offset = tlv::find_tlv(&tlvs, TAG_2)
        .filter(|t| t.value.len() == 2)
        .map(|t| ((t.value[0] as usize) << 8) | (t.value[1] as usize))
        .unwrap_or(0);

    let length = tlv::find_tlv(&tlvs, TAG_3)
        .filter(|t| t.value.len() == 2)
        .map(|t| ((t.value[0] as usize) << 8) | (t.value[1] as usize));

    match store.get(&obj_id) {
        Some(obj) => {
            let data = match obj {
                SecureObject::Binary { data } => {
                    // Reads beyond the file bounds fail 0x6985
                    // (bench-verified: offset 8 + length 16 on a
                    // 16-byte file); they are not truncated.
                    let end = match length {
                        Some(l) => offset + l,
                        None => data.len(),
                    };
                    if offset >= data.len() || end > data.len() {
                        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    data[offset..end].to_vec()
                }
                SecureObject::ECKeyPair { public_key, .. } => public_key.clone(),
                SecureObject::ECPublicKey { public_key, .. } => public_key.clone(),
                SecureObject::RSAKeyPair { private_key_der, .. } => {
                    // Return the public key components (modulus) for RSA
                    // For simplicity, return the DER-encoded public key
                    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
                    if let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs1_der(private_key_der) {
                        let pub_key = rsa::RsaPublicKey::from(&priv_key);
                        pub_key.to_pkcs1_der().map(|d| d.as_bytes().to_vec()).unwrap_or_default()
                    } else {
                        vec![]
                    }
                }
                SecureObject::AESKey { .. } => {
                    // Like HMACKey below: symmetric key objects are
                    // never exported, not even with an attached
                    // POLICY_OBJ_ALLOW_READ. Bench-verified 0x6986 on
                    // SE051 applet 7.2.0 and SE050C applet 3.1.1, with
                    // ReadObjectAttributes confirming the policy
                    // reached the chip (7.2 run).
                    return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
                }
                SecureObject::UserID { .. } => {
                    // UserID objects are authentication objects; their
                    // value is never readable (AN12413). Creation in
                    // plain sessions is refused on real parts, so this
                    // path only serves legacy simulator stores.
                    return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
                }
                SecureObject::Counter { value, size } => {
                    let be = value.to_be_bytes();
                    be[8 - (*size as usize)..].to_vec()
                }
                SecureObject::HMACKey { .. } => {
                    // The applet never exports an HMACKey object, not even
                    // with POLICY_OBJ_ALLOW_READ attached at creation:
                    // verified on SE051 applet 7.2.0 hardware, where
                    // ReadObject fails with SW 0x6986 although the object
                    // attributes confirm the read policy, and observed
                    // identically on SE050C applet 3.1.1.
                    return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
                }
            };
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &data)])
        }
        // Operations on missing objects fail 0x6985 on real applets
        // (bench-verified on 3.1.1 and 7.2.0), not 0x6A82.
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

fn handle_read_size(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    match store.get(&obj_id) {
        Some(obj) => {
            let size = obj.data_size() as u16;
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &size.to_be_bytes())])
        }
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// ReadIDList: request Tag1=2-byte offset, Tag2=1-byte type filter
/// (0xFF = all). Response Tag1 = more indicator (kSE05x_MoreIndicator:
/// 0x01 NO_MORE, 0x02 MORE), Tag2 = concatenated 4-byte IDs. The
/// simulator always returns the whole (filtered) list in one response.
fn handle_read_id_list(apdu: &ParsedApdu, store: &mut ObjectStore, v7: bool) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let offset = tlv::find_tlv(&tlvs, TAG_1)
        .filter(|t| t.value.len() == 2)
        .map(|t| ((t.value[0] as usize) << 8) | (t.value[1] as usize))
        .unwrap_or(0);

    let filter = tlv::find_tlv(&tlvs, TAG_2)
        .and_then(|t| t.value.first().copied())
        .unwrap_or(0xFF);

    let mut ids = store.list_ids();
    ids.sort();

    let mut id_bytes = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        if i < offset {
            continue;
        }
        if filter != 0xFF && filter != 0x00 {
            let matches = store
                .get(id)
                .map(|obj| obj.type_code(v7) == filter)
                .unwrap_or(false);
            if !matches {
                continue;
            }
        }
        id_bytes.extend_from_slice(id);
    }

    ApduResponse::success_with_tlvs(&[
        Tlv::new(TAG_1, &[0x01]), // kSE05x_MoreIndicator_NO_MORE
        Tlv::new(TAG_2, &id_bytes),
    ])
}

fn handle_read_type(apdu: &ParsedApdu, store: &mut ObjectStore, v7: bool) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    match store.get(&obj_id) {
        Some(obj) => {
            let type_code = obj.type_code(v7);
            // Tag1 = type, Tag2 = transient indicator. The simulator
            // only models persistent objects (0x01); real applets
            // report 0x02 for objects created with INS_TRANSIENT.
            ApduResponse::success_with_tlvs(&[
                Tlv::new(TAG_1, &[type_code]),
                Tlv::new(TAG_2, &[0x01]),
            ])
        }
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Applet 7.2 object attribute layout for a non-authentication object:
/// id, type, auth indicator, AEAD tag length, owner auth ID, RFU, policy,
/// origin and object version. Applet 3.1.1 rejects this command.
fn handle_read_attributes(
    apdu: &ParsedApdu,
    store: &mut ObjectStore,
    v7: bool,
) -> ApduResponse {
    if !v7 {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };
    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };
    let Some(object) = store.get(&obj_id) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let mut attributes = Vec::new();
    attributes.extend_from_slice(&obj_id);
    attributes.push(object.type_code(true));
    attributes.push(0x01); // kSE05x_SetIndicator_NOT_SET
    attributes.extend_from_slice(&[0x00, 0x00]); // minimum AEAD tag length
    attributes.extend_from_slice(&[0x00; 4]); // owner: unauthenticated session
    attributes.extend_from_slice(&[0x00, 0x00]); // RFU
    if let Some(metadata) = store.metadata(&obj_id) {
        if let Some(policy) = &metadata.policy {
            attributes.extend_from_slice(policy);
        }
        attributes.push(metadata.origin);
    } else {
        attributes.push(0x01); // legacy store: treat as externally created
    }
    attributes.extend_from_slice(&[0x00; 4]); // object version

    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_3, &attributes)])
}

fn handle_check_exists(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let result = if store.exists(&obj_id) { 0x01u8 } else { 0x02u8 };
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[result])])
}

fn handle_delete(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    if !store.policy_allows(&obj_id, crate::policy::POLICY_OBJ_ALLOW_DELETE) {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Deleting a nonexistent object fails 0x6985 (bench-verified on
    // applet 3.1.1 and 7.2.0; the SDK's erase-before-create pattern
    // logs a warning for it and continues).
    if store.remove(&obj_id).is_none() {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    ApduResponse::success()
}

#[cfg(test)]
mod read_policy_tests {
    use super::*;
    use crate::policy::POLICY_OBJ_ALLOW_READ;

    fn read_apdu(obj_id: [u8; 4]) -> ParsedApdu {
        ParsedApdu {
            cla: 0x80,
            ins: INS_READ,
            p1: P1_DEFAULT,
            p2: P2_DEFAULT,
            data: vec![TAG_1, 0x04, obj_id[0], obj_id[1], obj_id[2], obj_id[3]],
            le: None,
        }
    }

    #[test]
    fn test_read_hmackey_without_policy_returns_6986() {
        // An HMACKey object created with no policy attached cannot be
        // read back on any real applet generation (observed on applet
        // 3.1.1 and 7.2 hardware alike), so the ECDH shared secret
        // export fails unless the derive target was created with a
        // read policy.
        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x66],
            SecureObject::HMACKey { key: vec![0xAB; 32], policy: None });
        let resp = handle_read(&read_apdu([0, 0, 0, 0x66]), &mut store, true);
        assert_eq!(resp.sw, SW_COMMAND_NOT_ALLOWED);
    }

    #[test]
    fn test_read_hmackey_policy_without_read_returns_6986() {
        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x66],
            SecureObject::HMACKey { key: vec![0xAB; 32], policy: Some(0x0014_0000) });
        let resp = handle_read(&read_apdu([0, 0, 0, 0x66]), &mut store, true);
        assert_eq!(resp.sw, SW_COMMAND_NOT_ALLOWED);
    }

    #[test]
    fn test_read_hmackey_with_read_policy_still_denied() {
        // Hardware ground truth (SE051 applet 7.2.0): even an attached
        // POLICY_OBJ_ALLOW_READ does not make an HMACKey object readable.
        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x66],
            SecureObject::HMACKey {
                key: vec![0xAB; 32],
                policy: Some(POLICY_OBJ_ALLOW_READ | 0x0014_0000),
            });
        let resp = handle_read(&read_apdu([0, 0, 0, 0x66]), &mut store, true);
        assert_eq!(resp.sw, SW_COMMAND_NOT_ALLOWED);
    }

    #[test]
    fn test_read_aeskey_denied_regardless_of_policy() {
        // Hardware ground truth (SE051 7.2.0 + SE050C 3.1.1): AES key
        // objects behave exactly like HMACKey objects on ReadObject --
        // 0x6986 with no policy and with ALLOW_READ attached alike.
        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x69], SecureObject::AESKey { key: vec![0x11; 16] });
        let resp = handle_read(&read_apdu([0, 0, 0, 0x69]), &mut store, true);
        assert_eq!(resp.sw, SW_COMMAND_NOT_ALLOWED);
    }

    #[test]
    fn test_read_binary_without_policy_succeeds() {
        // Binary (file) objects stay readable with no policy attached;
        // only symmetric key objects are read-guarded. This is what the
        // pre-7.2 wolfSSL derive flow relies on.
        let data = vec![0xCDu8; 32];
        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x66],
            SecureObject::Binary { data: data.clone() });
        let resp = handle_read(&read_apdu([0, 0, 0, 0x66]), &mut store, true);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, data);
    }

    #[test]
    fn test_read_size_of_unreadable_hmackey_succeeds() {
        // Only the object content is policy-guarded; ReadSize must keep
        // working since sss_key_store_get_key sizes its buffer with it.
        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x66],
            SecureObject::HMACKey { key: vec![0xAB; 32], policy: None });
        let mut apdu = read_apdu([0, 0, 0, 0x66]);
        apdu.p2 = P2_SIZE;
        let resp = handle_read(&apdu, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn tag1_apdu(ins: u8, p1: u8, p2: u8, obj_id: [u8; 4]) -> ParsedApdu {
        ParsedApdu {
            cla: 0x80,
            ins,
            p1,
            p2,
            data: vec![TAG_1, 0x04, obj_id[0], obj_id[1], obj_id[2], obj_id[3]],
            le: None,
        }
    }

    #[test]
    fn test_delete_nonexistent_returns_6985() {
        // Bench-verified on applet 3.1.1 and 7.2.0 (HARDWARE_VALIDATION
        // ground truth #5).
        let mut store = ObjectStore::new();
        let apdu = tag1_apdu(INS_MGMT, P1_DEFAULT, P2_DELETE_OBJECT, [0x7F, 0, 0, 1]);
        assert_eq!(handle_mgmt(&apdu, &mut store).sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_read_missing_object_returns_6985() {
        // Bench-verified: ReadObject and ReadSize on a missing object
        // return 0x6985, not 0x6A82.
        let mut store = ObjectStore::new();
        let apdu = tag1_apdu(INS_READ, P1_DEFAULT, P2_DEFAULT, [0x7F, 0, 0, 2]);
        assert_eq!(handle_read(&apdu, &mut store, true).sw, SW_CONDITIONS_NOT_SATISFIED);
        let apdu = tag1_apdu(INS_READ, P1_DEFAULT, P2_SIZE, [0x7F, 0, 0, 2]);
        assert_eq!(handle_read(&apdu, &mut store, true).sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_write_userid_refused() {
        // Bench-verified: WriteUserID in a plain session -> 0x6985 on
        // both applet generations.
        let mut store = ObjectStore::new();
        let mut apdu = tag1_apdu(INS_WRITE, P1_USERID, P2_DEFAULT, [0x7F, 0, 0, 3]);
        apdu.data.extend_from_slice(&[TAG_2, 0x04, b'u', b's', b'e', b'r']);
        assert_eq!(handle_write(&apdu, &mut store).sw, SW_CONDITIONS_NOT_SATISFIED);
        assert!(store.get(&[0x7F, 0, 0, 3]).is_none());
    }

    fn write_binary_apdu(obj_id: [u8; 4], offset: u16, len: Option<u16>, data: &[u8])
        -> ParsedApdu
    {
        let mut body = vec![TAG_1, 0x04];
        body.extend_from_slice(&obj_id);
        body.extend_from_slice(&[TAG_2, 0x02, (offset >> 8) as u8, offset as u8]);
        if let Some(l) = len {
            body.extend_from_slice(&[TAG_3, 0x02, (l >> 8) as u8, l as u8]);
        }
        body.push(TAG_4);
        body.push(data.len() as u8);
        body.extend_from_slice(data);
        ParsedApdu { cla: 0x80, ins: INS_WRITE, p1: P1_BINARY, p2: P2_DEFAULT,
                     data: body, le: None }
    }

    fn attach_policy(apdu: &mut ParsedApdu, header: u32) -> Vec<u8> {
        let mut raw = vec![0x08];
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&header.to_be_bytes());
        let mut policy_tlv = vec![TAG_POLICY, raw.len() as u8];
        policy_tlv.extend_from_slice(&raw);
        policy_tlv.extend_from_slice(&apdu.data);
        apdu.data = policy_tlv;
        raw
    }

    #[test]
    fn test_policy_denies_overwrite_and_delete_when_permissions_are_missing() {
        let mut store = ObjectStore::new();
        let no_write_id = [0x7F, 0, 0, 0x31];
        let no_delete_id = [0x7F, 0, 0, 0x32];

        let mut create = write_binary_apdu(no_write_id, 0, Some(4), &[1, 2, 3, 4]);
        attach_policy(
            &mut create,
            crate::policy::POLICY_OBJ_ALLOW_READ
                | crate::policy::POLICY_OBJ_ALLOW_DELETE,
        );
        assert_eq!(handle_write(&create, &mut store).sw, SW_NO_ERROR);
        let overwrite = write_binary_apdu(no_write_id, 0, Some(4), &[9, 9, 9, 9]);
        assert_eq!(
            handle_write(&overwrite, &mut store).sw,
            SW_CONDITIONS_NOT_SATISFIED
        );
        match store.get(&no_write_id) {
            Some(SecureObject::Binary { data }) => assert_eq!(data, &[1, 2, 3, 4]),
            _ => panic!("binary object missing"),
        }

        let mut create = write_binary_apdu(no_delete_id, 0, Some(4), &[5, 6, 7, 8]);
        attach_policy(
            &mut create,
            crate::policy::POLICY_OBJ_ALLOW_READ
                | crate::policy::POLICY_OBJ_ALLOW_WRITE,
        );
        assert_eq!(handle_write(&create, &mut store).sw, SW_NO_ERROR);
        let delete = tag1_apdu(
            INS_MGMT,
            P1_DEFAULT,
            P2_DELETE_OBJECT,
            no_delete_id,
        );
        assert_eq!(
            handle_mgmt(&delete, &mut store).sw,
            SW_CONDITIONS_NOT_SATISFIED
        );
        assert!(store.exists(&no_delete_id));
    }

    #[test]
    fn test_read_attributes_returns_raw_policy_and_origin_on_v7() {
        let id = [0x7F, 0, 0, 0x33];
        let mut store = ObjectStore::new();
        let mut create = write_binary_apdu(id, 0, Some(3), &[1, 2, 3]);
        let raw_policy = attach_policy(
            &mut create,
            crate::policy::POLICY_OBJ_ALLOW_READ
                | crate::policy::POLICY_OBJ_ALLOW_DELETE,
        );
        assert_eq!(handle_write(&create, &mut store).sw, SW_NO_ERROR);

        let read = tag1_apdu(INS_READ, P1_DEFAULT, P2_ATTRIBUTES, id);
        let response = handle_read(&read, &mut store, true);
        assert_eq!(response.sw, SW_NO_ERROR);
        let tlvs = crate::tlv::parse_tlvs(&response.data).unwrap();
        let attributes = &tlv::find_tlv(&tlvs, TAG_3).unwrap().value;
        assert_eq!(&attributes[0..4], &id);
        assert_eq!(attributes[4], 0x0B);
        assert_eq!(&attributes[14..14 + raw_policy.len()], &raw_policy);
        assert_eq!(attributes[14 + raw_policy.len()], 0x01);
        assert_eq!(attributes.len(), 14 + raw_policy.len() + 1 + 4);

        assert_eq!(
            handle_read(&read, &mut store, false).sw,
            SW_CONDITIONS_NOT_SATISFIED
        );
    }

    #[test]
    fn test_binary_bounds_enforced() {
        // Bench-verified on a 16-byte file: write at offset 8 with 16
        // bytes -> 0x6A80 and the size stays 16; read offset 8 length
        // 16 -> 0x6985.
        let id = [0x7F, 0, 0, 4];
        let mut store = ObjectStore::new();
        let create = write_binary_apdu(id, 0, Some(16), &[0xC3; 16]);
        assert_eq!(handle_write(&create, &mut store).sw, 0x9000);

        let past_end = write_binary_apdu(id, 8, Some(16), &[0xC3; 16]);
        assert_eq!(handle_write(&past_end, &mut store).sw, SW_WRONG_DATA);
        match store.get(&id) {
            Some(SecureObject::Binary { data }) => assert_eq!(data.len(), 16),
            _ => panic!("binary object missing"),
        }

        let mut read = tag1_apdu(INS_READ, P1_DEFAULT, P2_DEFAULT, id);
        read.data.extend_from_slice(&[TAG_2, 0x02, 0x00, 0x08, TAG_3, 0x02, 0x00, 0x10]);
        assert_eq!(handle_read(&read, &mut store, true).sw, SW_CONDITIONS_NOT_SATISFIED);

        // In-bounds partial read still works.
        let mut read = tag1_apdu(INS_READ, P1_DEFAULT, P2_DEFAULT, id);
        read.data.extend_from_slice(&[TAG_2, 0x02, 0x00, 0x08, TAG_3, 0x02, 0x00, 0x08]);
        let resp = handle_read(&read, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
    }

    #[test]
    fn test_counter_create_set_inc_read() {
        // Bench-verified: a counter created with size 4 reads back
        // exactly 4 bytes and ReadSize reports 4.
        let id = [0x7F, 0, 0, 5];
        let mut store = ObjectStore::new();

        let mut create = tag1_apdu(INS_WRITE, P1_COUNTER, P2_DEFAULT, id);
        create.data.extend_from_slice(&[TAG_2, 0x02, 0x00, 0x04]);
        assert_eq!(handle_write(&create, &mut store).sw, 0x9000);

        let mut set = tag1_apdu(INS_WRITE, P1_COUNTER, P2_DEFAULT, id);
        set.data.extend_from_slice(&[TAG_3, 0x04, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(handle_write(&set, &mut store).sw, 0x9000);

        let inc = tag1_apdu(INS_WRITE, P1_COUNTER, P2_DEFAULT, id);
        assert_eq!(handle_write(&inc, &mut store).sw, 0x9000);

        let read = tag1_apdu(INS_READ, P1_DEFAULT, P2_DEFAULT, id);
        let resp = handle_read(&read, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value,
                   vec![0x01, 0x02, 0x03, 0x05]);

        let mut size = tag1_apdu(INS_READ, P1_DEFAULT, P2_SIZE, id);
        size.p2 = P2_SIZE;
        let resp = handle_read(&size, &mut store, true);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, vec![0x00, 0x04]);
    }

    #[test]
    fn test_read_id_list_format() {
        // Response format per the SDK parser: Tag1 = more indicator
        // (0x01 = NO_MORE), Tag2 = 4-byte IDs (bench-verified layout).
        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 1], SecureObject::Binary { data: vec![1, 2, 3] });
        store.insert([0, 0, 0, 2], SecureObject::AESKey { key: vec![0; 16] });

        let apdu = ParsedApdu {
            cla: 0x80, ins: INS_READ, p1: P1_DEFAULT, p2: P2_LIST,
            data: vec![TAG_1, 0x02, 0x00, 0x00, TAG_2, 0x01, 0xFF],
            le: None,
        };
        let resp = handle_read(&apdu, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, vec![0x01]);
        let ids = &tlv::find_tlv(&tlvs, TAG_2).unwrap().value;
        assert_eq!(ids.len(), 8);
        assert_eq!(&ids[..4], &[0, 0, 0, 1]);
        assert_eq!(&ids[4..], &[0, 0, 0, 2]);
    }

    #[test]
    fn test_read_type_version_dependent_ec_codes() {
        // Bench-verified: a P-256 pair reads type 0x29 on the SE051
        // (applet 7.2.0) and generic 0x01 on the SE050C (applet 3.1.1).
        use crate::object_store::types::ECCurve;
        let id = [0x7F, 0, 0, 6];
        let mut store = ObjectStore::new();
        store.insert(id, SecureObject::ECKeyPair {
            curve: ECCurve::NistP256,
            private_key: vec![0; 32],
            public_key: vec![0x04; 65],
        });
        let apdu = tag1_apdu(INS_READ, P1_DEFAULT, P2_TYPE, id);
        let resp = handle_read(&apdu, &mut store, true);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, vec![0x29]);

        let resp = handle_read(&apdu, &mut store, false);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, vec![0x01]);
    }
}
