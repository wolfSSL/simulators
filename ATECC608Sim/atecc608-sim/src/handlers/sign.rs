use crate::atca::{self, status, Command};
use crate::handlers::genkey::slot_scalar;
use crate::object_store::{Device, NUM_SLOTS};
use crate::session::Session;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

/// Sign command (opcode 0x41).
///
/// P1 mode byte:
///   Bit 7 (0x80) = External message mode (required in v1).
///   Bit 5 (0x20) = SOURCE_MSGDIGBUF — on ATECC608A, read the digest from
///                  the Message Digest Buffer rather than TempKey.
///   Bit 6 (0x40) = IncludeSlots/EUI48 — request signing auxiliary data.
/// We accept any variant with bit 7 set and use whichever digest was most
/// recently loaded via Nonce pass-through (both TempKey and MsgDigBuf land
/// in the same per-session scratch in our model).
/// P2 = key ID (slot holding the private key).
/// Response = 64-byte signature (r || s, big-endian).
pub fn handle(device: &Device, session: &mut Session, cmd: &Command) -> Vec<u8> {
    if cmd.p1 & 0x80 == 0 {
        // Internal-message Sign requires GenDig-produced TempKey state we
        // don't model.
        return atca::status_response(status::EXECUTION_ERROR);
    }
    let slot = cmd.p2 as usize;
    if slot >= NUM_SLOTS {
        return atca::status_response(status::PARSE_ERROR);
    }
    if !session.tempkey.valid {
        // Sign-external requires a digest to have been loaded via Nonce.
        return atca::status_response(status::EXECUTION_ERROR);
    }
    let scalar = match slot_scalar(device, slot) {
        Some(s) => s,
        None => return atca::status_response(status::EXECUTION_ERROR),
    };
    let sk = match SigningKey::from_bytes(&scalar.into()) {
        Ok(k) => k,
        Err(_) => return atca::status_response(status::EXECUTION_ERROR),
    };
    let digest = session.tempkey.value;
    let sig: Signature = match sk.sign_prehash(&digest) {
        Ok(s) => s,
        Err(_) => return atca::status_response(status::EXECUTION_ERROR),
    };
    let bytes = sig.to_bytes();
    // `bytes` is already r || s, 64 bytes, big-endian. Return as-is.
    atca::build_response(&bytes)
}
