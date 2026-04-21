/* ec.rs
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
use crate::object_store::types::{ECCurve, SecureObject};
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3, TAG_4, TAG_5, TAG_7};

use ecdsa::signature::{Signer, Verifier};
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use rand::rngs::OsRng;
use sha2::Digest;

/// Pad a hash to the curve's scalar size (right-pad with zeros).
/// ECDSA requires the hash to be at least as long as the curve order.
/// When the hash is shorter (e.g., SHA-1 on P-384), it must be padded.
fn pad_hash(data: &[u8], scalar_len: usize) -> Vec<u8> {
    if data.len() >= scalar_len {
        data[..scalar_len].to_vec()
    } else {
        // Left-pad with zeros to preserve big-endian integer value
        let mut padded = vec![0u8; scalar_len];
        padded[scalar_len - data.len()..].copy_from_slice(data);
        padded
    }
}

/// Handle WRITE EC key command (key generation when P2=Default and no private key data).
pub fn handle_write_ec_key(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Extract object ID from Tag1
    let obj_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Extract curve from Tag2
    let curve = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => match ECCurve::from_se050_byte(t.value[0]) {
            Some(c) => c,
            None => return ApduResponse::error(SW_WRONG_DATA),
        },
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // Check what key data is provided
    let private_key_data = tlv::find_tlv(&tlvs, TAG_3).map(|t| t.value.clone());
    let public_key_data = tlv::find_tlv(&tlvs, TAG_4)
        .or_else(|| tlv::find_tlv(&tlvs, TAG_2).filter(|t| t.value.len() > 4))
        .map(|t| t.value.clone());

    if apdu.key_type() == P1_KEY_PAIR && private_key_data.is_none() {
        // Generate a new key pair
        match curve {
            ECCurve::NistP224 => generate_p224_keypair(obj_id, store),
            ECCurve::NistP256 => generate_p256_keypair(obj_id, store),
            ECCurve::NistP384 => generate_p384_keypair(obj_id, store),
            ECCurve::Ed25519 => generate_ed25519_keypair(obj_id, store),
            ECCurve::Curve25519 => generate_x25519_keypair(obj_id, store),
        }
    } else if let Some(priv_key) = private_key_data {
        // Import private key (with optional public key)
        import_ec_key(obj_id, curve, &priv_key, apdu.key_type(), store)
    } else if apdu.key_type() == P1_PUBLIC_KEY {
        // Import public key only
        let pub_key = public_key_data.unwrap_or_default();
        store.insert(
            obj_id,
            SecureObject::ECPublicKey {
                curve,
                public_key: pub_key,
            },
        );
        ApduResponse::success()
    } else {
        ApduResponse::error(SW_WRONG_DATA)
    }
}

fn generate_p224_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = p224::ecdsa::SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP224,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
}

fn generate_p256_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP256,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
}

fn generate_p384_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = p384::ecdsa::SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP384,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
}

fn generate_ed25519_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Ed25519 keys are NOT reversed by the SDK on write (unlike Curve25519).
    // Store in native LE format.
    store.insert(
        obj_id,
        SecureObject::ECKeyPair {
            curve: ECCurve::Ed25519,
            private_key: signing_key.to_bytes().to_vec(),
            public_key: verifying_key.to_bytes().to_vec(),
        },
    );

    ApduResponse::success()
}

fn generate_x25519_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);

    // SE050 stores 25519 keys reversed (BE). SDK reverses on read.
    let mut priv_bytes = secret.to_bytes();
    priv_bytes.reverse();
    let mut pub_bytes = public.to_bytes();
    pub_bytes.reverse();

    store.insert(
        obj_id,
        SecureObject::ECKeyPair {
            curve: ECCurve::Curve25519,
            private_key: priv_bytes.to_vec(),
            public_key: pub_bytes.to_vec(),
        },
    );

    ApduResponse::success()
}

fn import_ec_key(
    obj_id: [u8; 4],
    curve: ECCurve,
    private_key_data: &[u8],
    _key_type: u8,
    store: &mut ObjectStore,
) -> ApduResponse {
    // Ed25519 verify needs the stored public key (ed25519_dalek cannot derive
    // a verifying key from a signature alone). Derive it at import time.
    // ECC verify paths derive pub-from-priv on demand so they don't need this.
    let public_key = match curve {
        ECCurve::Ed25519 if private_key_data.len() == 32 => {
            let mut priv_bytes = [0u8; 32];
            priv_bytes.copy_from_slice(private_key_data);
            ed25519_dalek::SigningKey::from_bytes(&priv_bytes)
                .verifying_key()
                .to_bytes()
                .to_vec()
        }
        _ => vec![],
    };
    store.insert(
        obj_id,
        SecureObject::ECKeyPair {
            curve,
            private_key: private_key_data.to_vec(),
            public_key,
        },
    );
    ApduResponse::success()
}

fn p224_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    let Ok(sk) = p224::ecdsa::SigningKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let hash = pad_hash(data, 28);
    let sig: Result<p224::ecdsa::Signature, _> = sk.sign_prehash(&hash);
    let Ok(sig) = sig else { return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED) };
    let der = p224::ecdsa::DerSignature::from(sig);
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, der.as_bytes())])
}
fn p256_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    let Ok(sk) = p256::ecdsa::SigningKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let hash = pad_hash(data, 32);
    let sig: Result<p256::ecdsa::Signature, _> = sk.sign_prehash(&hash);
    let Ok(sig) = sig else { return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED) };
    let der = p256::ecdsa::DerSignature::from(sig);
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, der.as_bytes())])
}
fn p384_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    let Ok(sk) = p384::ecdsa::SigningKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let hash = pad_hash(data, 48);
    let sig: Result<p384::ecdsa::Signature, _> = sk.sign_prehash(&hash);
    let Ok(sig) = sig else { return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED) };
    let der = p384::ecdsa::DerSignature::from(sig);
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, der.as_bytes())])
}

fn p224_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = p224::ecdsa::SigningKey::from_bytes(private_key.into()) else { return false };
    let vk = sk.verifying_key();
    let Ok(sig) = p224::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 28);
    vk.verify_prehash(&hash, &sig).is_ok()
}
fn p256_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = p256::ecdsa::SigningKey::from_bytes(private_key.into()) else { return false };
    let vk = sk.verifying_key();
    let Ok(sig) = p256::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 32);
    vk.verify_prehash(&hash, &sig).is_ok()
}
fn p384_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = p384::ecdsa::SigningKey::from_bytes(private_key.into()) else { return false };
    let vk = sk.verifying_key();
    let Ok(sig) = p384::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 48);
    vk.verify_prehash(&hash, &sig).is_ok()
}

/// Handle signature generation (EC + RSA).
/// INS=Crypto, P1=Signature, P2=Sign
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=data
pub fn handle_sign(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    // Tag3 = data to sign (optional — EdDSA can sign empty messages)
    let input_data = tlv::find_tlv(&tlvs, TAG_3)
        .map(|t| t.value.clone())
        .unwrap_or_default();

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_sign(private_key, &input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_sign(private_key, &input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_sign(private_key, &input_data)
        }
        SecureObject::ECKeyPair {
            curve: ECCurve::Ed25519,
            private_key,
            ..
        } => {
            if private_key.len() != 32 {
                return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
            }
            // Ed25519: SDK does NOT reverse on write, so stored in native LE
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(private_key);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            use ed25519_dalek::Signer;
            let sig = signing_key.sign(&input_data);
            let sig_bytes = sig.to_bytes();
            // SDK reverses each 32-byte half (R, S) of Ed25519 signatures
            // after reading from SE050. Store reversed so SDK produces correct output.
            let mut out_bytes = sig_bytes;
            out_bytes[..32].reverse();
            out_bytes[32..].reverse();
            ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &out_bytes)])
        }
        SecureObject::RSAKeyPair { .. } => {
            super::rsa::handle_rsa_sign(&key_obj, algo, &input_data)
        }
        _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Handle signature verification (EC + RSA).
/// INS=Crypto, P1=Signature, P2=Verify
/// EC: Tag1=key_id, Tag2=algo, Tag3=data, Tag5=signature
/// RSA: Tag1=key_id, Tag2=algo, Tag3=data, Tag3(bug)=signature
pub fn handle_verify(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    // Get data from Tag3. Data is pre-hashed (digest) for ECDSA verify.
    // EdDSA verify can have an empty message, so TAG_3 may be absent.
    let tag3_entries = tlv::find_tlvs(&tlvs, TAG_3);
    let input_data = tag3_entries.first().map(|t| t.value.clone()).unwrap_or_default();

    // Signature: try Tag5 first (correct per spec), then second Tag3 (driver bug)
    let sig_data = if let Some(t) = tlv::find_tlv(&tlvs, TAG_5) {
        t.value.clone()
    } else if tag3_entries.len() >= 2 {
        tag3_entries[1].value.clone()
    } else {
        return ApduResponse::error(SW_WRONG_DATA);
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let result = match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECPublicKey { curve: ECCurve::NistP224, public_key } => {
            p224_verify_pubkey(public_key, &input_data, &sig_data)
        }
        SecureObject::ECPublicKey { curve: ECCurve::NistP256, public_key } => {
            p256_verify_pubkey(public_key, &input_data, &sig_data)
        }
        SecureObject::ECPublicKey { curve: ECCurve::NistP384, public_key } => {
            p384_verify_pubkey(public_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair {
            curve: ECCurve::Ed25519,
            public_key,
            ..
        } => {
            if public_key.len() != 32 || sig_data.len() != 64 {
                return ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[0x02])]);
            }
            // Ed25519: stored in native LE
            let mut pk_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(public_key);
            let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) else {
                return ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[0x02])]);
            };
            // SDK reverses each 32-byte half before sending to SE050
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&sig_data);
            sig_bytes[..32].reverse();
            sig_bytes[32..].reverse();
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            use ed25519_dalek::Verifier;
            verifying_key.verify(&input_data, &signature).is_ok()
        }
        SecureObject::RSAKeyPair { .. } => {
            return super::rsa::handle_rsa_verify(&key_obj, algo, &input_data, &sig_data);
        }
        _ => {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    let result_byte = if result { 0x01 } else { 0x02 };
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[result_byte])])
}

/// Handle ECDH shared secret generation.
/// INS=Crypto, P1=EC, P2=DH(0x0F)
/// Tag1=privateKeyID(4B), Tag2=peerPublicKey, Tag7=sharedSecretOutputID(4B)
/// The shared secret is stored as a binary object at sharedSecretOutputID.
pub fn handle_ecdh(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    let peer_pubkey = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => &t.value,
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let output_id = match tlv::find_tlv(&tlvs, TAG_7) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            id
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_FILE_NOT_FOUND),
    };

    let shared_secret = match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::Curve25519, private_key, .. } => {
            x25519_ecdh(private_key, peer_pubkey)
        }
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    match shared_secret {
        Some(secret) => {
            store.insert(output_id, SecureObject::Binary { data: secret.clone() });
            ApduResponse::success()
        }
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// Verify using raw public key bytes (for ECPublicKey objects)
fn p224_verify_pubkey(public_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(vk) = p224::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else { return false };
    let Ok(sig) = p224::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 28);
    vk.verify_prehash(&hash, &sig).is_ok()
}
fn p256_verify_pubkey(public_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else { return false };
    let Ok(sig) = p256::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 32);
    vk.verify_prehash(&hash, &sig).is_ok()
}
fn p384_verify_pubkey(public_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(vk) = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else { return false };
    let Ok(sig) = p384::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 48);
    vk.verify_prehash(&hash, &sig).is_ok()
}

fn p224_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    let sk = p224::SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = p224::PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = p224::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

fn p256_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    let sk = p256::SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = p256::PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

fn p384_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    let sk = p384::SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = p384::PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

fn x25519_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    if private_key.len() != 32 || peer_pubkey.len() != 32 {
        return None;
    }
    // Both stored reversed (BE) — reverse to LE for X25519
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(private_key);
    sk_bytes.reverse();
    // Peer pubkey from Tag2 is also BE (read directly from SE050 storage)
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(peer_pubkey);
    pk_bytes.reverse();
    let sk = x25519_dalek::StaticSecret::from(sk_bytes);
    let pk = x25519_dalek::PublicKey::from(pk_bytes);
    let shared = sk.diffie_hellman(&pk);
    Some(shared.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p384_sign_verify_20byte_hash() {
        // Test P-384 sign/verify with 20-byte hash (SHA-1) via handler functions
        let sk = p384::ecdsa::SigningKey::random(&mut OsRng);
        let private_key = sk.to_bytes().to_vec();
        let public_key = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();

        let hash = [0x42u8; 20]; // 20-byte SHA-1 hash

        // Sign via p384_sign (which pads to 48 bytes)
        let resp = p384_sign(&private_key, &hash);
        assert_eq!(resp.sw, 0x9000, "p384_sign failed");

        // Extract DER signature from TLV response
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        let sig_der = &tlvs[0].value;

        // Verify via handler functions (which also pad)
        assert!(p384_verify(&private_key, &hash, sig_der), "p384_verify with 20-byte hash failed");
        assert!(p384_verify_pubkey(&public_key, &hash, sig_der), "p384_verify_pubkey with 20-byte hash failed");
    }

    #[test]
    fn test_p384_sign_verify_48byte_hash() {
        let sk = p384::ecdsa::SigningKey::random(&mut OsRng);
        let private_key = sk.to_bytes().to_vec();

        let hash = [0xCD; 48]; // 48-byte SHA-384 hash
        let resp = p384_sign(&private_key, &hash);
        assert_eq!(resp.sw, 0x9000);

        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert!(p384_verify(&private_key, &hash, &tlvs[0].value));
    }
}

#[cfg(test)]
mod test_ed25519_vector {
    #[test]
    fn test_ed25519_rfc8032_vector1() {
        // RFC 8032 test vector 1: sign empty message
        let skey1 = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let expected_sig = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&skey1);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(b"");
        
        assert_eq!(sig.to_bytes().to_vec(), expected_sig,
            "Ed25519 signature mismatch for empty message");
    }
}
