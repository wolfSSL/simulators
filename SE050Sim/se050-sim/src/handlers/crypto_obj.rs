/* crypto_obj.rs
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
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3};

/// Handle CreateCryptoObject.
/// INS=WRITE, P1=CRYPTO_OBJ(0x10), P2=DEFAULT(0x00)
/// Tag1=cryptoObjectID(2B), Tag2=cryptoContext(1B), Tag3=subtype(1B)
pub fn handle_create(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let context_type = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let subtype = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) if !t.value.is_empty() => t.value[0],
        _ => 0x00,
    };

    store.crypto_object_types.insert(crypto_id, (context_type, subtype));
    ApduResponse::success()
}

/// Handle ReadCryptoObjectList.
/// INS=READ, P1=CRYPTO_OBJ(0x10), P2=LIST(0x25)
pub fn handle_list(_apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let mut data = Vec::new();
    for (&id, &(ctx_type, subtype)) in &store.crypto_object_types {
        data.push((id >> 8) as u8);
        data.push(id as u8);
        data.push(ctx_type);
        data.push(subtype);
    }
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &data)])
}

/// Handle DeleteCryptoObject.
/// INS=MGMT, P1=CRYPTO_OBJ(0x10), P2=DELETE_OBJECT(0x28)
/// Tag1=cryptoObjectID(2B)
pub fn handle_delete(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    let crypto_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 2 => ((t.value[0] as u16) << 8) | (t.value[1] as u16),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    store.crypto_object_types.remove(&crypto_id);
    store.crypto_objects.remove(&crypto_id);
    ApduResponse::success()
}
