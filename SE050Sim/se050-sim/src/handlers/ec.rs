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

use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use rand::rngs::OsRng;

// p192 0.13 ships no SecretKey/SigningKey conveniences (verification
// only); the generic elliptic-curve types work with its arithmetic.
use elliptic_curve::sec1::ToEncodedPoint;
type P192SecretKey = elliptic_curve::SecretKey<p192::NistP192>;
type P192PublicKey = elliptic_curve::PublicKey<p192::NistP192>;

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
pub fn handle_write_ec_key(
    apdu: &ParsedApdu,
    store: &mut ObjectStore,
    version: crate::applet::AppletVersion,
) -> ApduResponse {
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

    // Extract curve from Tag2
    let (curve_byte, curve) = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if !t.value.is_empty() => match ECCurve::from_se050_byte(t.value[0]) {
            Some(c) => (t.value[0], c),
            None => return ApduResponse::error(SW_WRONG_DATA),
        },
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    // The SE052F's appletConfig clears both the EDDSA and DH_MONT
    // feature bits, and the part refuses key generation on either 25519
    // curve with 0x6985 (bench-verified). Imports are refused here too,
    // which follows from the feature being absent rather than from a
    // separate measurement.
    if matches!(curve, ECCurve::Ed25519 | ECCurve::Curve25519)
        && !version.supports_25519()
    {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Weierstrass curves must exist as fully parameterized curve
    // objects before any key can be created on them; key generation on
    // a missing or param-less curve fails 0x6985 (bench-verified on
    // applet 3.1.1 and 7.2.0). The 25519 curves are chip constants.
    if curve.needs_curve_object() && !store.curve_ready(curve_byte) {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Check what key data is provided
    let private_key_data = tlv::find_tlv(&tlvs, TAG_3).map(|t| t.value.clone());
    let public_key_data = tlv::find_tlv(&tlvs, TAG_4)
        .or_else(|| tlv::find_tlv(&tlvs, TAG_2).filter(|t| t.value.len() > 4))
        .map(|t| t.value.clone());

    let generated = apdu.key_type() == P1_KEY_PAIR && private_key_data.is_none();
    let response = if generated {
        // Generate a new key pair
        match curve {
            ECCurve::NistP192 => generate_p192_keypair(obj_id, store),
            ECCurve::NistP224 => generate_p224_keypair(obj_id, store),
            ECCurve::NistP256 => generate_p256_keypair(obj_id, store),
            ECCurve::NistP384 => generate_p384_keypair(obj_id, store),
            ECCurve::NistP521 => generate_p521_keypair(obj_id, store),
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

fn generate_p192_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = P192SecretKey::random(&mut OsRng);
    let pk = sk.public_key();
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP192,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
}

fn generate_p521_keypair(obj_id: [u8; 4], store: &mut ObjectStore) -> ApduResponse {
    let sk = p521::ecdsa::SigningKey::random(&mut OsRng);
    let pk = p521::ecdsa::VerifyingKey::from(&sk);
    store.insert(obj_id, SecureObject::ECKeyPair {
        curve: ECCurve::NistP521,
        private_key: sk.to_bytes().to_vec(),
        public_key: pk.to_encoded_point(false).as_bytes().to_vec(),
    });
    ApduResponse::success()
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
    // Derive the public key from the private key at import time for every
    // curve. Ed25519 verify needs it (ed25519_dalek cannot derive a verifying
    // key from a signature alone), and ReadObject returns the public part of
    // an asymmetric object, which hosts parse (e.g. wc_ecc_use_key_id reads
    // the public key back after importing a private-only key).
    let public_key = match curve {
        ECCurve::Ed25519 if private_key_data.len() == 32 => {
            let mut priv_bytes = [0u8; 32];
            priv_bytes.copy_from_slice(private_key_data);
            ed25519_dalek::SigningKey::from_bytes(&priv_bytes)
                .verifying_key()
                .to_bytes()
                .to_vec()
        }
        ECCurve::NistP192 if private_key_data.len() == 24 => {
            match P192SecretKey::from_bytes(private_key_data.into()) {
                Ok(sk) => sk.public_key().to_encoded_point(false).as_bytes().to_vec(),
                Err(_) => vec![],
            }
        }
        ECCurve::NistP521 if private_key_data.len() == 66 => {
            match p521::ecdsa::SigningKey::from_bytes(private_key_data.into()) {
                Ok(sk) => p521::ecdsa::VerifyingKey::from(&sk)
                    .to_encoded_point(false).as_bytes().to_vec(),
                Err(_) => vec![],
            }
        }
        ECCurve::NistP224 if private_key_data.len() == 28 => {
            match p224::ecdsa::SigningKey::from_bytes(private_key_data.into()) {
                Ok(sk) => sk.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
                Err(_) => vec![],
            }
        }
        ECCurve::NistP256 if private_key_data.len() == 32 => {
            match p256::ecdsa::SigningKey::from_bytes(private_key_data.into()) {
                Ok(sk) => sk.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
                Err(_) => vec![],
            }
        }
        ECCurve::NistP384 if private_key_data.len() == 48 => {
            match p384::ecdsa::SigningKey::from_bytes(private_key_data.into()) {
                Ok(sk) => sk.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
                Err(_) => vec![],
            }
        }
        ECCurve::Curve25519 if private_key_data.len() == 32 => {
            // Stored reversed (BE) like generate_x25519_keypair: reverse the
            // private key to LE, derive, store the public key reversed again.
            let mut priv_bytes = [0u8; 32];
            priv_bytes.copy_from_slice(private_key_data);
            priv_bytes.reverse();
            let secret = x25519_dalek::StaticSecret::from(priv_bytes);
            let mut pub_bytes = x25519_dalek::PublicKey::from(&secret).to_bytes();
            pub_bytes.reverse();
            pub_bytes.to_vec()
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

// kSE05x_ECSignatureAlgo digest sizes. The applet requires the signed
// input to be exactly the digest length of the selected algorithm
// (bench-verified on applet 3.1.1 and 7.2.0: SHA256 with 20 bytes and
// SHA512 with 32 bytes both fail 0x6985, SHA1 with 20 and SHA512 with
// 64 succeed). PLAIN (0x09) takes a raw value at curve scalar size.
fn ecdsa_algo_digest_len(algo: u8) -> Option<usize> {
    match algo {
        0x11 => Some(20), // SHA1
        0x25 => Some(28), // SHA224
        0x21 => Some(32), // SHA256
        0x22 => Some(48), // SHA384
        0x26 => Some(64), // SHA512
        _ => None,
    }
}

/// Validate the (algo, input length) pairing for a Weierstrass ECDSA
/// operation. Returns Some(error) when the request must be refused.
fn check_ecdsa_algo(algo: u8, input_len: usize, scalar_len: usize) -> Option<ApduResponse> {
    match ecdsa_algo_digest_len(algo) {
        Some(dlen) if input_len == dlen => None,
        Some(_) => Some(ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED)),
        None if algo == 0x09 /* PLAIN */ => {
            if input_len == scalar_len {
                None
            } else {
                Some(ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED))
            }
        }
        None => Some(ApduResponse::error(SW_WRONG_DATA)),
    }
}

/// Raw ECDSA signing over p192's arithmetic. The p192 crate only
/// implements the verify primitive, so the textbook signing equation
/// s = k^-1 (e + r d) is computed here with a random per-signature k;
/// output correctness is checked against p192's own VerifyingKey in
/// the unit tests.
fn p192_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    use elliptic_curve::ops::Reduce;
    use elliptic_curve::point::AffineCoordinates;
    use elliptic_curve::Field;

    let Ok(sk) = P192SecretKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let d = *sk.to_nonzero_scalar();
    let hash = pad_hash(data, 24);
    let e = <p192::Scalar as Reduce<elliptic_curve::bigint::U192>>::reduce_bytes(
        p192::FieldBytes::from_slice(&hash));

    for _ in 0..64 {
        let k = p192::Scalar::random(&mut OsRng);
        let Some(k_inv) = Option::<p192::Scalar>::from(k.invert()) else { continue };
        let r_point = (p192::ProjectivePoint::GENERATOR * k).to_affine();
        let r = <p192::Scalar as Reduce<elliptic_curve::bigint::U192>>::reduce_bytes(
            &r_point.x());
        if bool::from(r.is_zero()) {
            continue;
        }
        let s = k_inv * (e + r * d);
        if bool::from(s.is_zero()) {
            continue;
        }
        let Ok(sig) = p192::ecdsa::Signature::from_scalars(r, s) else { continue };
        let der = sig.to_der();
        return ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, der.as_bytes())]);
    }
    ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED)
}
fn p521_sign(private_key: &[u8], data: &[u8]) -> ApduResponse {
    let Ok(sk) = p521::ecdsa::SigningKey::from_bytes(private_key.into()) else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };
    let hash = pad_hash(data, 66);
    let sig: Result<p521::ecdsa::Signature, _> = sk.sign_prehash(&hash);
    let Ok(sig) = sig else { return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED) };
    let der = sig.to_der();
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, der.as_bytes())])
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

fn p192_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = P192SecretKey::from_bytes(private_key.into()) else { return false };
    let pub_point = sk.public_key().to_encoded_point(false);
    p192_verify_pubkey(pub_point.as_bytes(), data, sig_data)
}
fn p521_verify(private_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(sk) = p521::ecdsa::SigningKey::from_bytes(private_key.into()) else { return false };
    let vk = p521::ecdsa::VerifyingKey::from(&sk);
    let Ok(sig) = p521::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 66);
    vk.verify_prehash(&hash, &sig).is_ok()
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
        // Missing objects fail 0x6985 on real applets (bench-verified
        // on 3.1.1 and 7.2.0), not 0x6A82.
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Weierstrass ECDSA enforces input length == algo digest length.
    if let SecureObject::ECKeyPair { curve, .. } = &key_obj {
        if curve.needs_curve_object() {
            if let Some(err) = check_ecdsa_algo(algo, input_data.len(), curve.scalar_len()) {
                return err;
            }
        }
    }

    match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP192, private_key, .. } => {
            p192_sign(private_key, &input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_sign(private_key, &input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_sign(private_key, &input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_sign(private_key, &input_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP521, private_key, .. } => {
            p521_sign(private_key, &input_data)
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
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Same digest-length contract as ECDSASign (the sign direction is
    // bench-verified; verify is assumed to share the applet's check).
    let wcurve = match &key_obj {
        SecureObject::ECKeyPair { curve, .. } => Some(curve),
        SecureObject::ECPublicKey { curve, .. } => Some(curve),
        _ => None,
    };
    if let Some(curve) = wcurve {
        if curve.needs_curve_object() {
            if let Some(err) = check_ecdsa_algo(algo, input_data.len(), curve.scalar_len()) {
                return err;
            }
        }
    }

    let result = match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP192, private_key, .. } => {
            p192_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP521, private_key, .. } => {
            p521_verify(private_key, &input_data, &sig_data)
        }
        SecureObject::ECPublicKey { curve: ECCurve::NistP192, public_key } => {
            p192_verify_pubkey(public_key, &input_data, &sig_data)
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
        SecureObject::ECPublicKey { curve: ECCurve::NistP521, public_key } => {
            p521_verify_pubkey(public_key, &input_data, &sig_data)
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

/// Whether the applet 7.2 strict ECDH InObject contract is enforced.
/// Off by default so hosts that predate the contract keep working; set
/// SE050_SIM_STRICT_ECDH=1 to enforce it. The direct (Tag7-less)
/// variant is valid in both modes, and ReadObject on HMACKey objects is
/// always refused regardless of this switch or any attached policy, as
/// on real applets (see object_mgmt::handle_read).
pub fn strict_ecdh_from_env() -> bool {
    std::env::var("SE050_SIM_STRICT_ECDH").map(|v| v == "1").unwrap_or(false)
}

/// Handle ECDH shared secret generation.
/// INS=Crypto, P1=EC, P2=DH(0x0F)
/// Tag1=privateKeyID(4B), Tag2=peerPublicKey, Tag7=sharedSecretOutputID(4B,
/// optional).
/// Without Tag7 this is the direct variant
/// (Se05x_API_ECDHGenerateSharedSecret): the shared secret is returned in
/// the response Tag1 and no object is created; big endian for Montgomery
/// curves, as on real applets. This is the only way a host can obtain the
/// secret on applet >= 7.2, which refuses to export symmetric key objects
/// regardless of policy (verified on SE051 applet 7.2.0 hardware).
/// With Tag7 this is the InObject variant: the target must reference an
/// existing HMACKey object whose size equals the shared secret exactly,
/// otherwise the applet returns SW_CONDITIONS_NOT_SATISFIED; the secret
/// overwrites that object's value (little endian for Montgomery, matching
/// the SDK convention).
/// With `strict` false (the default, see strict_ecdh_from_env) a missing
/// InObject target instead falls back to the legacy simulator behavior of
/// implicitly creating a Binary object, so hosts that predate the applet
/// 7.2 contract keep working. A pre-existing HMACKey target gets the
/// exact-size contract in both modes.
pub fn handle_ecdh(apdu: &ParsedApdu, store: &mut ObjectStore, strict: bool) -> ApduResponse {
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

    // Tag7 absent selects the direct variant
    // (Se05x_API_ECDHGenerateSharedSecret): the shared secret is returned
    // in the response and no object is touched. Tag7 present selects the
    // InObject variant. Both are valid on every real applet generation;
    // the strict target contract only applies to the InObject form.
    let output_id: Option<[u8; 4]> = match tlv::find_tlv(&tlvs, TAG_7) {
        Some(t) if t.value.len() == 4 => {
            let mut id = [0u8; 4];
            id.copy_from_slice(&t.value);
            Some(id)
        }
        Some(_) => return ApduResponse::error(SW_WRONG_DATA),
        None => None,
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    // On the real applet the Tag7 target must already exist as an HMACKey
    // object; the applet refuses to create it implicitly. In lenient mode a
    // missing (or non-HMACKey) target keeps the legacy implicit-create
    // behavior instead (target None).
    let target = match output_id {
        Some(oid) => match store.get(&oid) {
            Some(SecureObject::HMACKey { key, policy }) =>
                Some((key.len(), *policy)),
            _ if strict => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
            _ => None,
        },
        None => None,
    };

    let is_mont = matches!(&key_obj,
        SecureObject::ECKeyPair { curve: ECCurve::Curve25519, .. });

    let shared_secret = match &key_obj {
        SecureObject::ECKeyPair { curve: ECCurve::NistP192, private_key, .. } => {
            p192_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP224, private_key, .. } => {
            p224_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP256, private_key, .. } => {
            p256_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP384, private_key, .. } => {
            p384_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::NistP521, private_key, .. } => {
            p521_ecdh(private_key, peer_pubkey)
        }
        SecureObject::ECKeyPair { curve: ECCurve::Curve25519, private_key, .. } => {
            x25519_ecdh(private_key, peer_pubkey)
        }
        _ => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    match shared_secret {
        Some(secret) => {
            let oid = match output_id {
                None => {
                    // Direct variant: the secret goes out in the response.
                    // The applet speaks big endian for Montgomery curves
                    // (the middleware byte swaps around the call), while
                    // the InObject store below keeps the little endian
                    // convention the SDK reads back.
                    let mut resp = secret;
                    if is_mont {
                        resp.reverse();
                    }
                    return ApduResponse::success_with_tlvs(
                        &[Tlv::new(TAG_1, &resp)]);
                }
                Some(oid) => oid,
            };
            match target {
                Some((len, policy)) => {
                    if secret.len() != len {
                        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
                    }
                    // The derive overwrites the object's value; the policy
                    // attached at creation stays with the object.
                    store.insert(oid, SecureObject::HMACKey { key: secret, policy });
                }
                None => {
                    // Legacy lenient behavior: implicitly create the target
                    // as a Binary object.
                    store.insert(oid, SecureObject::Binary { data: secret });
                }
            }
            ApduResponse::success()
        }
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// Verify using raw public key bytes (for ECPublicKey objects)
fn p192_verify_pubkey(public_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(vk) = p192::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else { return false };
    let Ok(sig) = p192::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 24);
    vk.verify_prehash(&hash, &sig).is_ok()
}
fn p521_verify_pubkey(public_key: &[u8], data: &[u8], sig_data: &[u8]) -> bool {
    let Ok(vk) = p521::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else { return false };
    let Ok(sig) = p521::ecdsa::Signature::from_der(sig_data) else { return false };
    let hash = pad_hash(data, 66);
    vk.verify_prehash(&hash, &sig).is_ok()
}
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

fn p192_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    // p192 0.13 has no ecdh cargo feature; the generic elliptic-curve
    // diffie_hellman works with its arithmetic implementation.
    let sk = P192SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = P192PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = elliptic_curve::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

fn p521_ecdh(private_key: &[u8], peer_pubkey: &[u8]) -> Option<Vec<u8>> {
    let sk = p521::SecretKey::from_bytes(private_key.into()).ok()?;
    let peer_pk = p521::PublicKey::from_sec1_bytes(peer_pubkey).ok()?;
    let shared = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer_pk.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
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

    fn tlv_bytes(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    /// Build an ECDHGenerateSharedSecret_InObject APDU and a store holding a
    /// P-256 key pair at 0x64. Returns (apdu, store, expected_secret).
    fn ecdh_inobject_fixture() -> (ParsedApdu, ObjectStore, Vec<u8>) {
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let private_key = sk.to_bytes().to_vec();
        let public_key = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();

        let peer = p256::ecdsa::SigningKey::random(&mut OsRng);
        let peer_pub = peer.verifying_key().to_encoded_point(false).as_bytes().to_vec();

        let expected = p256_ecdh(&private_key, &peer_pub).unwrap();

        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x64], SecureObject::ECKeyPair {
            curve: ECCurve::NistP256,
            private_key,
            public_key,
        });

        let mut data = tlv_bytes(TAG_1, &[0, 0, 0, 0x64]);
        data.extend(tlv_bytes(TAG_2, &peer_pub));
        data.extend(tlv_bytes(TAG_7, &[0, 0, 0, 0x66]));

        let apdu = ParsedApdu {
            cla: 0x80,
            ins: 0x03,
            p1: P1_EC,
            p2: P2_DH,
            data,
            le: None,
        };
        (apdu, store, expected)
    }

    #[test]
    fn test_ecdh_strict_tag7_target_missing_returns_6985() {
        // Applet 7.2 behavior: the Tag7 HMACKey object must be pre-created,
        // otherwise SW_CONDITIONS_NOT_SATISFIED. This is the failure mode of
        // wolfSSL's se050_ecc_shared_secret against middleware built for
        // applet >= 07_02 (never creates the target object).
        let (apdu, mut store, _) = ecdh_inobject_fixture();
        let resp = handle_ecdh(&apdu, &mut store, true);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
        assert!(store.get(&[0, 0, 0, 0x66]).is_none());
    }

    #[test]
    fn test_ecdh_strict_tag7_wrong_type_target_returns_6985() {
        let (apdu, mut store, _) = ecdh_inobject_fixture();
        store.insert([0, 0, 0, 0x66], SecureObject::Binary { data: vec![0u8; 32] });
        let resp = handle_ecdh(&apdu, &mut store, true);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_ecdh_tag7_wrong_size_hmackey_returns_6985_both_modes() {
        // The exact-size contract applies whenever the target exists as an
        // HMACKey, in strict and lenient mode alike.
        for strict in [true, false] {
            let (apdu, mut store, _) = ecdh_inobject_fixture();
            store.insert([0, 0, 0, 0x66],
                SecureObject::HMACKey { key: vec![0u8; 16], policy: None });
            let resp = handle_ecdh(&apdu, &mut store, strict);
            assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED, "strict={}", strict);
        }
    }

    #[test]
    fn test_ecdh_tag7_precreated_hmackey_succeeds_both_modes() {
        for strict in [true, false] {
            let (apdu, mut store, expected) = ecdh_inobject_fixture();
            store.insert([0, 0, 0, 0x66],
                SecureObject::HMACKey { key: vec![0u8; 32], policy: None });
            let resp = handle_ecdh(&apdu, &mut store, strict);
            assert_eq!(resp.sw, 0x9000, "strict={}", strict);
            match store.get(&[0, 0, 0, 0x66]) {
                Some(SecureObject::HMACKey { key, .. }) => assert_eq!(key, &expected),
                other => panic!("expected HMACKey with shared secret, got {:?}", other.is_some()),
            }
        }
    }

    #[test]
    fn test_ecdh_direct_no_tag7_returns_secret_both_modes() {
        // Without Tag7 the applet returns the shared secret in the
        // response and touches no object, in strict and lenient mode
        // alike. This is how hosts on applet >= 7.2 obtain the secret.
        for strict in [true, false] {
            let (mut apdu, mut store, expected) = ecdh_inobject_fixture();
            // Rebuild the request without the Tag7 TLV, extracting the
            // peer public key by TLV parsing rather than fixed offsets.
            let orig = crate::tlv::parse_tlvs(&apdu.data).unwrap();
            let peer = tlv::find_tlv(&orig, TAG_2).unwrap().value.clone();
            let mut data = tlv_bytes(TAG_1, &[0, 0, 0, 0x64]);
            data.extend(tlv_bytes(TAG_2, &peer));
            apdu.data = data;
            let count_before = store.count();
            let resp = handle_ecdh(&apdu, &mut store, strict);
            assert_eq!(resp.sw, 0x9000, "strict={}", strict);
            let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
            assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, expected,
                "strict={}", strict);
            assert_eq!(store.count(), count_before, "no object may be created");
            assert!(store.get(&[0, 0, 0, 0x66]).is_none());
        }
    }

    #[test]
    fn test_ecdh_direct_x25519_secret_is_big_endian() {
        // The applet speaks big endian for Montgomery curves; the SDK
        // swaps around the direct call. Keys are stored reversed (BE).
        let sk = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);
        let peer_sk = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let peer_pk = x25519_dalek::PublicKey::from(&peer_sk);
        let mut expected_be = sk.diffie_hellman(&peer_pk).to_bytes().to_vec();
        expected_be.reverse();

        let mut priv_be = sk.to_bytes().to_vec();
        priv_be.reverse();
        let mut pub_be = pk.to_bytes().to_vec();
        pub_be.reverse();
        let mut peer_be = peer_pk.to_bytes().to_vec();
        peer_be.reverse();

        let mut store = ObjectStore::new();
        store.insert([0, 0, 0, 0x64], SecureObject::ECKeyPair {
            curve: ECCurve::Curve25519,
            private_key: priv_be,
            public_key: pub_be,
        });
        let mut data = tlv_bytes(TAG_1, &[0, 0, 0, 0x64]);
        data.extend(tlv_bytes(TAG_2, &peer_be));
        let apdu = ParsedApdu {
            cla: 0x80, ins: 0x03, p1: P1_EC, p2: P2_DH, data, le: None,
        };
        let resp = handle_ecdh(&apdu, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlv::find_tlv(&tlvs, TAG_1).unwrap().value, expected_be);
    }

    #[test]
    fn test_ecdh_preserves_target_policy() {
        // The policy attached when the derive target was created must
        // survive the derive overwriting the value, or a subsequent
        // strict-mode ReadObject of the shared secret would be refused.
        let (apdu, mut store, expected) = ecdh_inobject_fixture();
        let policy = Some(crate::policy::POLICY_OBJ_ALLOW_READ);
        store.insert([0, 0, 0, 0x66],
            SecureObject::HMACKey { key: vec![0u8; 32], policy });
        let resp = handle_ecdh(&apdu, &mut store, true);
        assert_eq!(resp.sw, 0x9000);
        match store.get(&[0, 0, 0, 0x66]) {
            Some(SecureObject::HMACKey { key, policy: p }) => {
                assert_eq!(key, &expected);
                assert_eq!(*p, policy);
            }
            other => panic!("expected HMACKey, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn test_import_private_only_p256_derives_public() {
        // wc_ecc_use_key_id imports a private-only key pair and then reads
        // the public part back via ReadObject, so import must derive it.
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let expected_pub = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();

        let mut store = ObjectStore::new();
        let resp = import_ec_key([0, 0, 0, 0x32], ECCurve::NistP256,
            &sk.to_bytes().to_vec(), P1_KEY_PAIR, &mut store);
        assert_eq!(resp.sw, 0x9000);
        match store.get(&[0, 0, 0, 0x32]) {
            Some(SecureObject::ECKeyPair { public_key, .. }) => {
                assert_eq!(public_key, &expected_pub);
            }
            other => panic!("expected ECKeyPair, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn test_import_private_only_x25519_derives_public() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let mut expected_pub = x25519_dalek::PublicKey::from(&secret).to_bytes();
        expected_pub.reverse();
        let mut priv_be = secret.to_bytes();
        priv_be.reverse();

        let mut store = ObjectStore::new();
        let resp = import_ec_key([0, 0, 0, 0x33], ECCurve::Curve25519,
            &priv_be, P1_KEY_PAIR, &mut store);
        assert_eq!(resp.sw, 0x9000);
        match store.get(&[0, 0, 0, 0x33]) {
            Some(SecureObject::ECKeyPair { public_key, .. }) => {
                assert_eq!(public_key, &expected_pub.to_vec());
            }
            other => panic!("expected ECKeyPair, got {:?}", other.is_some()),
        }
    }

    fn sign_apdu(key_id: [u8; 4], algo: u8, data: &[u8]) -> ParsedApdu {
        let mut body = tlv_bytes(TAG_1, &key_id);
        body.extend(tlv_bytes(TAG_2, &[algo]));
        body.extend(tlv_bytes(TAG_3, data));
        ParsedApdu {
            cla: 0x80,
            ins: 0x03,
            p1: crate::apdu::P1_SIGNATURE,
            p2: crate::apdu::P2_SIGN,
            data: body,
            le: None,
        }
    }

    #[test]
    fn test_ecdsa_sign_enforces_algo_digest_length() {
        // Bench-verified on applet 3.1.1 and 7.2.0: the input must be
        // exactly the digest length of the ECSignatureAlgo. SHA256
        // with 20 bytes and SHA512 with 32 bytes fail 0x6985; SHA1
        // with 20 bytes and SHA512 with 64 bytes (truncated to the
        // leftmost 32 by the chip, host-verified) succeed.
        let key_id = [0, 0, 0, 0x80];
        let mut store = ObjectStore::new();
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        store.insert(key_id, SecureObject::ECKeyPair {
            curve: ECCurve::NistP256,
            private_key: sk.to_bytes().to_vec(),
            public_key: sk.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
        });

        let resp = handle_sign(&sign_apdu(key_id, 0x21, &[0x11; 20]), &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED, "SHA256 algo + 20B input");
        let resp = handle_sign(&sign_apdu(key_id, 0x26, &[0x22; 32]), &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED, "SHA512 algo + 32B input");
        let resp = handle_sign(&sign_apdu(key_id, 0x11, &[0x33; 20]), &mut store);
        assert_eq!(resp.sw, 0x9000, "SHA1 algo + 20B input");
        let resp = handle_sign(&sign_apdu(key_id, 0x26, &[0x33; 64]), &mut store);
        assert_eq!(resp.sw, 0x9000, "SHA512 algo + 64B input");
        // Unknown algo byte is a request error, not a state error.
        let resp = handle_sign(&sign_apdu(key_id, 0x7E, &[0x33; 32]), &mut store);
        assert_eq!(resp.sw, SW_WRONG_DATA);
        // Missing key object: 0x6985 as on hardware.
        let resp = handle_sign(&sign_apdu([9, 9, 9, 9], 0x21, &[0x33; 32]), &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_p521_full_flow_with_curve_provisioning() {
        // Bench-verified on both parts: keygen on a param-less curve
        // fails 0x6985; after SetECCurveParam uploads all five
        // parameters it succeeds, ReadSize reports 66, and a SHA-512
        // sign works (P-521 uses the whole 64-byte digest).
        use crate::dispatch::dispatch;
        let mut store = ObjectStore::new();
        store.curve_delete(0x05);
        store.curve_create(0x05); // param-less

        let key_id = [0, 0, 0, 0x81];
        let mut body = tlv_bytes(TAG_1, &key_id);
        body.extend(tlv_bytes(TAG_2, &[0x05]));
        let keygen = ParsedApdu {
            cla: 0x80,
            ins: 0x01,
            p1: crate::apdu::P1_EC | crate::apdu::P1_KEY_PAIR,
            p2: crate::apdu::P2_DEFAULT,
            data: body,
            le: None,
        };
        assert_eq!(dispatch(&keygen, &mut store, false).sw, SW_CONDITIONS_NOT_SATISFIED);

        for param in [0x01, 0x02, 0x04, 0x08, 0x10] {
            store.curve_add_param(0x05, param);
        }
        assert_eq!(dispatch(&keygen, &mut store, false).sw, 0x9000);
        match store.get(&key_id) {
            Some(SecureObject::ECKeyPair { curve: ECCurve::NistP521, public_key, .. }) => {
                assert_eq!(public_key.len(), 133, "uncompressed P-521 point");
            }
            other => panic!("expected P-521 pair, got {:?}", other.is_some()),
        }

        let resp = handle_sign(&sign_apdu(key_id, 0x26, &[0x44; 64]), &mut store);
        assert_eq!(resp.sw, 0x9000);
    }

    #[test]
    fn test_p192_sign_verifies_with_p192_crate() {
        // The hand-rolled P-192 signing (p192 0.13 implements only the
        // verify primitive) must produce signatures the crate's own
        // VerifyingKey accepts.
        let sk = P192SecretKey::random(&mut OsRng);
        let priv_bytes = sk.to_bytes().to_vec();
        let pub_bytes = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
        let digest = [0x55u8; 20];

        let resp = p192_sign(&priv_bytes, &digest);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        let der = &tlv::find_tlv(&tlvs, TAG_1).unwrap().value;
        assert!(p192_verify_pubkey(&pub_bytes, &digest, der));
        assert!(p192_verify(&priv_bytes, &digest, der));
        // ECDH round-trip between two P-192 keys.
        let sk2 = P192SecretKey::random(&mut OsRng);
        let pub2 = sk2.public_key().to_encoded_point(false).as_bytes().to_vec();
        let s1 = p192_ecdh(&priv_bytes, &pub2).unwrap();
        let s2 = p192_ecdh(&sk2.to_bytes().to_vec(), &pub_bytes).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 24);
    }

    #[test]
    fn test_ecdh_lenient_tag7_target_missing_creates_binary() {
        // Legacy behavior for hosts that predate the applet 7.2 contract:
        // a missing target is implicitly created as a Binary object.
        let (apdu, mut store, expected) = ecdh_inobject_fixture();
        let resp = handle_ecdh(&apdu, &mut store, false);
        assert_eq!(resp.sw, 0x9000);
        match store.get(&[0, 0, 0, 0x66]) {
            Some(SecureObject::Binary { data }) => assert_eq!(data, &expected),
            other => panic!("expected Binary with shared secret, got {:?}", other.is_some()),
        }
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

#[cfg(test)]
mod test_se052f_curves {
    use super::*;
    use crate::applet::AppletVersion;

    fn keygen_apdu(obj_id: [u8; 4], curve_byte: u8) -> ParsedApdu {
        let mut data = Vec::new();
        data.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        data.extend_from_slice(&Tlv::new(TAG_2, &[curve_byte]).encode());
        ParsedApdu {
            cla: 0x80,
            ins: crate::apdu::INS_WRITE,
            p1: crate::apdu::P1_EC | P1_KEY_PAIR,
            p2: crate::apdu::P2_DEFAULT,
            data,
            le: None,
        }
    }

    #[test]
    fn se052f_refuses_25519_curves() {
        // Bench-verified on real SE052F silicon: its appletConfig
        // (0x26f2) clears EDDSA and DH_MONT, and key generation on
        // either 25519 curve is refused 0x6985. NIST curves still work,
        // and the other personalities keep serving 25519.
        let mut store = ObjectStore::new();
        let obj_id = [0x7Fu8, 0x50, 0x00, 0x01];

        for (name, curve_byte) in [("Ed25519", 0x40u8), ("X25519", 0x41)] {
            let resp = handle_write_ec_key(
                &keygen_apdu(obj_id, curve_byte), &mut store,
                AppletVersion::V7_2_22F);
            assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED, "{}", name);
            assert!(!store.exists(&obj_id), "{} must not be created", name);

            let resp = handle_write_ec_key(
                &keygen_apdu(obj_id, curve_byte), &mut store,
                AppletVersion::V7_2_0);
            assert_eq!(resp.sw, 0x9000, "{} on the SE051 personality", name);
            assert!(store.exists(&obj_id));
            store.remove(&obj_id);
        }

        // P-256 (curve id 0x03) is unaffected on the SE052F.
        let resp = handle_write_ec_key(
            &keygen_apdu(obj_id, 0x03), &mut store, AppletVersion::V7_2_22F);
        assert_eq!(resp.sw, 0x9000, "SE052F still generates NIST keys");
        assert!(store.exists(&obj_id));
    }
}
