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
        P1_USERID => handle_write_userid(apdu, store),
        P1_COUNTER => handle_write_counter(apdu, store),
        _ => ApduResponse::error(SW_WRONG_P1P2),
    }
}

/// Handle READ commands for objects.
pub fn handle_read(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    match apdu.p2 {
        P2_DEFAULT => handle_read_object(apdu, store),
        P2_SIZE => handle_read_size(apdu, store),
        P2_LIST => handle_read_id_list(apdu, store),
        P2_TYPE => handle_read_type(apdu, store),
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

fn handle_write_binary(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Find object ID - could be in TAG_1 or after a policy TLV
    // The driver sends: Policy(opt), Tag1=objID, Tag2=offset, Tag3=length, Tag4=data
    let mut obj_id = None;
    let mut data = None;
    let mut offset: u16 = 0;

    for tlv in &tlvs {
        match tlv.tag {
            TAG_POLICY => {} // Skip policy
            TAG_1 if obj_id.is_none() && tlv.value.len() == 4 => {
                let mut id = [0u8; 4];
                id.copy_from_slice(&tlv.value);
                obj_id = Some(id);
            }
            TAG_2 if tlv.value.len() == 2 => {
                offset = ((tlv.value[0] as u16) << 8) | (tlv.value[1] as u16);
            }
            TAG_3 => {} // file length - we handle dynamically
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

    let write_data = data.unwrap_or_default();

    // If object exists, update at offset; otherwise create new
    if let Some(SecureObject::Binary { data: existing }) = store.get_mut(&obj_id) {
        let end = offset as usize + write_data.len();
        if end > existing.len() {
            existing.resize(end, 0);
        }
        existing[offset as usize..end].copy_from_slice(&write_data);
        // Need to persist manually since we mutated in place
        // Re-insert triggers persistence
        let updated = SecureObject::Binary { data: existing.clone() };
        store.insert(obj_id, updated);
    } else {
        if offset > 0 {
            let mut full_data = vec![0u8; offset as usize + write_data.len()];
            full_data[offset as usize..].copy_from_slice(&write_data);
            store.insert(obj_id, SecureObject::Binary { data: full_data });
        } else {
            store.insert(obj_id, SecureObject::Binary { data: write_data });
        }
    }

    ApduResponse::success()
}

fn handle_write_userid(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let mut obj_id = None;
    let mut value = None;

    for tlv in &tlvs {
        match tlv.tag {
            TAG_POLICY => {}
            TAG_1 if obj_id.is_none() && tlv.value.len() == 4 => {
                let mut id = [0u8; 4];
                id.copy_from_slice(&tlv.value);
                obj_id = Some(id);
            }
            TAG_2 => {
                value = Some(tlv.value.clone());
            }
            _ => {}
        }
    }

    let obj_id = match obj_id {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    store.insert(
        obj_id,
        SecureObject::UserID {
            value: value.unwrap_or_default(),
        },
    );
    ApduResponse::success()
}

fn handle_write_counter(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let obj_id = match extract_object_id(&tlvs) {
        Some(id) => id,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Initial value from Tag3 if present, otherwise 0
    let initial = tlv::find_tlv(&tlvs, TAG_3)
        .map(|t| {
            let mut val = 0u64;
            for &b in &t.value {
                val = (val << 8) | (b as u64);
            }
            val
        })
        .unwrap_or(0);

    store.insert(obj_id, SecureObject::Counter { value: initial });
    ApduResponse::success()
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
                    let end = length.map(|l| (offset + l).min(data.len())).unwrap_or(data.len());
                    if offset >= data.len() {
                        vec![]
                    } else {
                        data[offset..end].to_vec()
                    }
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
                SecureObject::AESKey { key } => key.clone(),
                SecureObject::UserID { value } => value.clone(),
                SecureObject::Counter { value } => value.to_be_bytes().to_vec(),
                SecureObject::HMACKey { key } => key.clone(),
            };
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &data)])
        }
        None => ApduResponse::error(SW_FILE_NOT_FOUND),
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
        None => ApduResponse::error(SW_FILE_NOT_FOUND),
    }
}

fn handle_read_id_list(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Tag1 = 2-byte offset
    let offset = tlv::find_tlv(&tlvs, TAG_1)
        .filter(|t| t.value.len() == 2)
        .map(|t| ((t.value[0] as usize) << 8) | (t.value[1] as usize))
        .unwrap_or(0);

    let ids = store.list_ids();
    let mut result = Vec::new();

    // First byte: MoreIndicator (0x00 = no more, 0x01 = more)
    result.push(0x00);

    // Append 4-byte object IDs starting from offset
    for (i, id) in ids.iter().enumerate() {
        if i >= offset {
            result.extend_from_slice(id);
        }
    }

    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &result)])
}

fn handle_read_type(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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
            let type_code = obj.type_code();
            // Tag1 = type, Tag2 = transient indicator (0x01 = persistent)
            ApduResponse::success_with_tlvs(&[
                Tlv::new(TAG_1, &[type_code]),
                Tlv::new(TAG_2, &[0x01]),
            ])
        }
        None => ApduResponse::error(SW_FILE_NOT_FOUND),
    }
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

    store.remove(&obj_id);
    ApduResponse::success()
}
