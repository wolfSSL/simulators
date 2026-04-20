use crate::apdu::{ApduResponse, ParsedApdu, P2_VERSION, P2_MEMORY, P2_RANDOM, P2_DELETE_ALL};
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1};
use rand::RngCore;

pub fn handle(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    match apdu.p2 {
        P2_VERSION => handle_get_version(apdu, store),
        P2_MEMORY => handle_get_free_memory(apdu, store),
        P2_RANDOM => handle_get_random(apdu, store),
        P2_DELETE_ALL => handle_delete_all(apdu, store),
        _ => ApduResponse::error(0x6A86),
    }
}

/// GetVersion: returns TLV[Tag1] with 7-byte version info.
fn handle_get_version(_apdu: &ParsedApdu, _store: &mut ObjectStore) -> ApduResponse {
    let version_data: [u8; 7] = [0x07, 0x02, 0x00, 0x6F, 0xFF, 0x01, 0x0B];
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &version_data)])
}

/// GetFreeMemory: returns TLV[Tag1] with 4-byte free memory value.
fn handle_get_free_memory(_apdu: &ParsedApdu, _store: &mut ObjectStore) -> ApduResponse {
    // Report 100KB free memory
    let free_memory: u32 = 102400;
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &free_memory.to_be_bytes())])
}

/// GetRandom: reads TLV[Tag1] as 2-byte requested length, returns random bytes.
fn handle_get_random(apdu: &ParsedApdu, _store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(0x6A80),
    };

    let tag1 = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) => t,
        None => return ApduResponse::error(0x6A80),
    };

    if tag1.value.len() < 2 {
        return ApduResponse::error(0x6A80);
    }

    let requested_len = ((tag1.value[0] as usize) << 8) | (tag1.value[1] as usize);
    let mut random_data = vec![0u8; requested_len];
    rand::thread_rng().fill_bytes(&mut random_data);

    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &random_data)])
}

/// DeleteAll: clears all objects from the store.
fn handle_delete_all(_apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    store.clear();
    ApduResponse::success()
}
