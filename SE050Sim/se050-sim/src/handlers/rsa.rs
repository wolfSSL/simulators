/* rsa.rs
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
use crate::object_store::types::{RsaComponents, SecureObject};
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2, TAG_3};

use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::signature::SignatureEncoding;
use sha2::digest::{const_oid::AssociatedOid, Digest, FixedOutputReset};

// SE050 WriteRSAKey TLV tag assignments (AN12413 §4.7.1).
const TAG_RSA_P: u8 = 0x43;      // TAG_3
const TAG_RSA_Q: u8 = 0x44;      // TAG_4
const TAG_RSA_DP: u8 = 0x45;     // TAG_5
const TAG_RSA_DQ: u8 = 0x46;     // TAG_6
const TAG_RSA_QINV: u8 = 0x47;   // TAG_7
const TAG_RSA_PUB_EXP: u8 = 0x48; // TAG_8
const TAG_RSA_PRIV: u8 = 0x49;   // TAG_9
const TAG_RSA_PUB_MOD: u8 = 0x4A; // TAG_10

/// Handle WRITE RSA key. Serves two scenarios:
///
/// * **Keygen** — a single APDU carrying only `TAG_2` (size in bits) with no
///   key components. The simulator generates a fresh key.
/// * **Import** — one or more APDUs each carrying a subset of
///   `{p,q,dp,dq,qInv,pubExp,priv,pubMod}`. The SDK splits DER key material
///   across multiple APDUs (see `sss_se05x_key_store_set_rsa_key`), so the
///   simulator accumulates components in `RSAKeyPair::staged` and materializes
///   a PKCS#1 DER once the set is sufficient (N+E+D, or CRT primes+E+N).
///
/// P1 = `P1_RSA | key_part`, P2 = `rsa_format`. Tags 3-10 per the map above.
///
/// On a personality without RSA support (SE050E) the applet refuses
/// keygen with SW 0x6985 and any APDU carrying key material with SW
/// 0x6A80 (both bench-verified on real SE050E silicon).
pub fn handle_write_rsa_key(
    apdu: &ParsedApdu,
    store: &mut ObjectStore,
    version: crate::applet::AppletVersion,
) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };

    if !version.supports_rsa() {
        let has_component = tlvs.iter().any(|t| {
            (TAG_RSA_P..=TAG_RSA_PUB_MOD).contains(&t.tag)
        });
        return ApduResponse::error(if has_component {
            SW_WRONG_DATA
        } else {
            SW_CONDITIONS_NOT_SATISFIED
        });
    }

    // The SE052F has RSA but refuses a public-key import with 0x6A80,
    // while generating a key pair on the same part works. Bench-verified
    // with the key part set to Public and modulus + exponent in one
    // APDU.
    //
    // Two APDU shapes mean "import a public key", and both are refused
    // so the restriction cannot be sidestepped: the applet's own
    // discriminator (the P1 key-part bits), and an APDU that simply
    // carries a complete public key -- modulus and exponent -- with no
    // private component. The second form was not exercised on silicon;
    // it is refused because it is the same operation reached through a
    // different encoding.
    //
    // The private-key import path is deliberately left alone. The
    // wolfCrypt port imports (E, D, N) across three separate APDUs, so
    // no single APDU there carries modulus and exponent together
    // without private material, and none of them sets the public key
    // part. Refusing on the mere presence of a public component would
    // break that flow at its first APDU.
    if !version.supports_rsa_public_import() {
        let has_private_component = [
            TAG_RSA_P, TAG_RSA_Q, TAG_RSA_DP, TAG_RSA_DQ, TAG_RSA_QINV,
            TAG_RSA_PRIV,
        ]
        .iter()
        .any(|tag| tlv::find_tlv(&tlvs, *tag).is_some());
        let carries_whole_public_key = tlv::find_tlv(&tlvs, TAG_RSA_PUB_MOD).is_some()
            && tlv::find_tlv(&tlvs, TAG_RSA_PUB_EXP).is_some()
            && !has_private_component;
        if apdu.key_type() == P1_PUBLIC_KEY || carries_whole_public_key {
            return ApduResponse::error(SW_WRONG_DATA);
        }
    }

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

    let size_bits_opt = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 2 => {
            Some(((t.value[0] as u16) << 8) | (t.value[1] as u16))
        }
        Some(_) => return ApduResponse::error(SW_WRONG_DATA),
        None => None,
    };

    // Collect any key-component TLVs present in this APDU.
    let comp_p    = tlv::find_tlv(&tlvs, TAG_RSA_P).map(|t| t.value.clone());
    let comp_q    = tlv::find_tlv(&tlvs, TAG_RSA_Q).map(|t| t.value.clone());
    let comp_dp   = tlv::find_tlv(&tlvs, TAG_RSA_DP).map(|t| t.value.clone());
    let comp_dq   = tlv::find_tlv(&tlvs, TAG_RSA_DQ).map(|t| t.value.clone());
    let comp_qinv = tlv::find_tlv(&tlvs, TAG_RSA_QINV).map(|t| t.value.clone());
    let comp_e    = tlv::find_tlv(&tlvs, TAG_RSA_PUB_EXP).map(|t| t.value.clone());
    let comp_d    = tlv::find_tlv(&tlvs, TAG_RSA_PRIV).map(|t| t.value.clone());
    let comp_n    = tlv::find_tlv(&tlvs, TAG_RSA_PUB_MOD).map(|t| t.value.clone());
    let has_any_component = comp_p.is_some() || comp_q.is_some() || comp_dp.is_some()
        || comp_dq.is_some() || comp_qinv.is_some() || comp_e.is_some()
        || comp_d.is_some() || comp_n.is_some();

    // A private-key import is a sequence of component APDUs. Missing WRITE
    // permission must not interrupt that creation transaction, but it does
    // deny a later replacement once a usable key has been materialized (or a
    // public-only N+E set is complete).
    let creation_in_progress = has_any_component && match store.get(&obj_id) {
        Some(SecureObject::RSAKeyPair { private_key_der, staged, .. }) => {
            if !private_key_der.is_empty() {
                false
            } else if apdu.key_type() == P1_PUBLIC_KEY {
                staged.n.is_none() || staged.e.is_none()
            } else {
                staged.n.is_none() || staged.e.is_none() || staged.d.is_none()
            }
        }
        _ => false,
    };
    if object_existed
        && !creation_in_progress
        && !store.policy_allows(&obj_id, crate::policy::POLICY_OBJ_ALLOW_WRITE)
    {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Keygen: size-only APDU, no component data — generate fresh.
    if !has_any_component {
        let Some(key_size_bits) = size_bits_opt else {
            return ApduResponse::error(SW_WRONG_DATA);
        };
        let key_size_usize = key_size_bits as usize;
        if ![1024, 2048, 3072, 4096].contains(&key_size_usize) {
            return ApduResponse::error(SW_WRONG_DATA);
        }
        // The SE052F refuses anything below 2048 bits with 0x6985
        // (bench-verified: 1024-bit CRT generation fails, 2048 works).
        if key_size_bits < version.rsa_min_key_bits() {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        }
        let Ok(private_key) = RsaPrivateKey::new(&mut OsRng, key_size_usize) else {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        };
        let Ok(der) = private_key.to_pkcs1_der() else {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        };
        store.insert(
            obj_id,
            SecureObject::RSAKeyPair {
                key_size_bits,
                private_key_der: der.as_bytes().to_vec(),
                staged: RsaComponents::default(),
            },
        );
        if !object_existed {
            store.set_creation_metadata(obj_id, creation_policy, 0x02);
        }
        return ApduResponse::success();
    }

    // Import path: merge components into a (possibly new) staged key object.
    let (mut size_bits, mut staged) = match store.get(&obj_id) {
        Some(SecureObject::RSAKeyPair { key_size_bits, staged, .. }) => {
            (*key_size_bits, staged.clone())
        }
        Some(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
        None => (0, RsaComponents::default()),
    };
    if let Some(sz) = size_bits_opt {
        size_bits = sz;
    }
    if let Some(v) = comp_p    { staged.p    = Some(v); }
    if let Some(v) = comp_q    { staged.q    = Some(v); }
    if let Some(v) = comp_dp   { staged.dp   = Some(v); }
    if let Some(v) = comp_dq   { staged.dq   = Some(v); }
    if let Some(v) = comp_qinv { staged.qinv = Some(v); }
    if let Some(v) = comp_e    { staged.e    = Some(v); }
    if let Some(v) = comp_d    { staged.d    = Some(v); }
    if let Some(v) = comp_n    { staged.n    = Some(v); }

    // Try to materialize a usable PKCS#1 DER from whatever we have now.
    let (private_key_der, staged) = match try_materialize(&staged) {
        Some(der) => (der, RsaComponents::default()),
        None => (Vec::new(), staged),
    };

    store.insert(
        obj_id,
        SecureObject::RSAKeyPair {
            key_size_bits: size_bits,
            private_key_der,
            staged,
        },
    );
    if !object_existed {
        store.set_creation_metadata(obj_id, creation_policy, 0x01);
    }
    ApduResponse::success()
}

/// Build PKCS#1 DER from staged components when we have at least (N, E, D).
/// CRT-only staging (primes without E/D/N) is not yet supported — the wolfCrypt
/// port uses `kSSS_CipherType_RSA` so the SDK sends (E, D, N) across three
/// APDUs; CRT-style imports would need key reconstruction from primes which
/// requires computing `d = e⁻¹ mod λ(n)`. Returns `None` if the set is not
/// yet sufficient, or if `RsaPrivateKey::from_components` rejects the inputs.
fn try_materialize(staged: &RsaComponents) -> Option<Vec<u8>> {
    let n_bytes = staged.n.as_deref()?;
    let e_bytes = staged.e.as_deref()?;
    let d_bytes = staged.d.as_deref()?;
    let n = BigUint::from_bytes_be(n_bytes);
    let e = BigUint::from_bytes_be(e_bytes);
    let d = BigUint::from_bytes_be(d_bytes);
    let primes = match (staged.p.as_deref(), staged.q.as_deref()) {
        (Some(p), Some(q)) => vec![BigUint::from_bytes_be(p), BigUint::from_bytes_be(q)],
        _ => vec![],
    };
    let key = RsaPrivateKey::from_components(n, e, d, primes).ok()?;
    key.to_pkcs1_der().ok().map(|d| d.as_bytes().to_vec())
}

/// Handle RSA sign command.
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=data
pub fn handle_rsa_sign(
    key_obj: &SecureObject,
    algo: u8,
    input_data: &[u8],
) -> ApduResponse {
    let SecureObject::RSAKeyPair { private_key_der, .. } = key_obj else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let private_key = match RsaPrivateKey::from_pkcs1_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let signature = match algo {
        // PKCS#1 v1.5 variants
        0x28 => pkcs1v15_sign::<sha2::Sha256>(&private_key, input_data),
        0x29 => pkcs1v15_sign::<sha2::Sha384>(&private_key, input_data),
        0x2A => pkcs1v15_sign::<sha2::Sha512>(&private_key, input_data),
        // PSS variants
        0x2C => pss_sign::<sha2::Sha256>(&private_key, input_data),
        0x2D => pss_sign::<sha2::Sha384>(&private_key, input_data),
        0x2E => pss_sign::<sha2::Sha512>(&private_key, input_data),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    match signature {
        Some(sig) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &sig)]),
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Build an `RsaPublicKey` from an RSA object, supporting both full keypair
/// imports (materialized `private_key_der`) and public-only imports (only N
/// and E staged). Returns `None` if neither form has enough material.
fn public_key_from_obj(key_obj: &SecureObject) -> Option<RsaPublicKey> {
    let SecureObject::RSAKeyPair { private_key_der, staged, .. } = key_obj else {
        return None;
    };
    if !private_key_der.is_empty() {
        return RsaPrivateKey::from_pkcs1_der(private_key_der)
            .ok()
            .map(|k| RsaPublicKey::from(&k));
    }
    let n = staged.n.as_deref()?;
    let e = staged.e.as_deref()?;
    RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)).ok()
}

/// Handle RSA verify command.
pub fn handle_rsa_verify(
    key_obj: &SecureObject,
    algo: u8,
    data: &[u8],
    signature: &[u8],
) -> ApduResponse {
    let public_key = match public_key_from_obj(key_obj) {
        Some(k) => k,
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let ok = match algo {
        // PKCS#1 v1.5 variants
        0x28 => pkcs1v15_verify::<sha2::Sha256>(&public_key, data, signature),
        0x29 => pkcs1v15_verify::<sha2::Sha384>(&public_key, data, signature),
        0x2A => pkcs1v15_verify::<sha2::Sha512>(&public_key, data, signature),
        // PSS variants
        0x2C => pss_verify::<sha2::Sha256>(&public_key, data, signature),
        0x2D => pss_verify::<sha2::Sha384>(&public_key, data, signature),
        0x2E => pss_verify::<sha2::Sha512>(&public_key, data, signature),
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    let result_byte = if ok { 0x01 } else { 0x02 };
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &[result_byte])])
}

/// Handle RSA encrypt oneshot.
/// P1=RSA(0x02), P2=EncryptOneshot(0x37)
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=plaintext
pub fn handle_rsa_encrypt(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    let plaintext = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let public_key = match public_key_from_obj(&key_obj) {
        Some(k) => k,
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let ciphertext = match algo {
        0x0A => public_key.encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext).ok(),
        0x0F => {
            // SE050's PKCS1_OAEP wire algo is SHA-1 only — the SDK maps
            // OAEP-SHA256/384/512 to `NA` (unsupported on this silicon).
            use rsa::Oaep;
            public_key
                .encrypt(&mut OsRng, Oaep::new::<sha1::Sha1>(), plaintext)
                .ok()
        }
        0x0C => {
            // NO_PAD: raw RSA public-key operation (m^e mod n). Used by
            // sss_se05x_asymmetric_verify_digest to recover the encoded
            // message from a signature so the SDK can compare on the host.
            use rsa::traits::PublicKeyParts;
            let m = rsa::BigUint::from_bytes_be(plaintext);
            let n = public_key.n();
            if &m >= n {
                return ApduResponse::error(SW_WRONG_DATA);
            }
            let c = m.modpow(public_key.e(), n);
            let mod_size = (n.bits() as usize + 7) / 8;
            let c_bytes = c.to_bytes_be();
            let mut padded = vec![0u8; mod_size];
            padded[mod_size - c_bytes.len()..].copy_from_slice(&c_bytes);
            Some(padded)
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    match ciphertext {
        Some(ct) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &ct)]),
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

/// Handle RSA decrypt oneshot.
/// P1=RSA(0x02), P2=DecryptOneshot(0x38)
/// Tag1=key_id(4B), Tag2=algo(1B), Tag3=ciphertext
pub fn handle_rsa_decrypt(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
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

    let ciphertext = match tlv::find_tlv(&tlvs, TAG_3) {
        Some(t) => &t.value,
        None => return ApduResponse::error(SW_WRONG_DATA),
    };

    let key_obj = match store.get(&key_id) {
        Some(obj) => obj.clone(),
        None => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let SecureObject::RSAKeyPair { private_key_der, .. } = &key_obj else {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    };

    let private_key = match RsaPrivateKey::from_pkcs1_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    };

    let result = match algo {
        0x0A => private_key.decrypt(Pkcs1v15Encrypt, ciphertext).ok(),
        0x0F => {
            // See handle_rsa_encrypt: SE050 PKCS1_OAEP = SHA-1 on the wire.
            use rsa::Oaep;
            private_key
                .decrypt(Oaep::new::<sha1::Sha1>(), ciphertext)
                .ok()
        }
        0x0C => {
            // NO_PAD: raw RSA private key operation (used by SDK for signing)
            // result = ciphertext^d mod n
            use rsa::traits::PublicKeyParts;
            let c = rsa::BigUint::from_bytes_be(ciphertext);
            rsa::hazmat::rsa_decrypt::<rand::rngs::OsRng>(None, &private_key, &c)
                .ok()
                .map(|m| {
                    // Left-pad to modulus size
                    let mod_size = private_key.n().bits() as usize / 8;
                    let m_bytes = m.to_bytes_be();
                    if m_bytes.len() < mod_size {
                        let mut padded = vec![0u8; mod_size];
                        padded[mod_size - m_bytes.len()..].copy_from_slice(&m_bytes);
                        padded
                    } else {
                        m_bytes
                    }
                })
        }
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };

    match result {
        Some(data) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &data)]),
        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---- Internal crypto helpers ----

fn pkcs1v15_sign<D>(private_key: &RsaPrivateKey, data: &[u8]) -> Option<Vec<u8>>
where
    D: Digest + AssociatedOid,
{
    use rsa::signature::Signer;
    let signing_key = rsa::pkcs1v15::SigningKey::<D>::new(private_key.clone());
    let sig = signing_key.sign(data);
    Some(sig.to_vec())
}

fn pkcs1v15_verify<D>(public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool
where
    D: Digest + AssociatedOid,
{
    use rsa::signature::Verifier;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<D>::new(public_key.clone());
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    verifying_key.verify(data, &sig).is_ok()
}

fn pss_sign<D>(private_key: &RsaPrivateKey, data: &[u8]) -> Option<Vec<u8>>
where
    D: Digest + FixedOutputReset,
{
    use rsa::signature::RandomizedSigner;
    let signing_key = rsa::pss::SigningKey::<D>::new(private_key.clone());
    let sig = signing_key.sign_with_rng(&mut OsRng, data);
    Some(sig.to_bytes().to_vec())
}

fn pss_verify<D>(public_key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool
where
    D: Digest + FixedOutputReset,
{
    use rsa::signature::Verifier;
    let verifying_key = rsa::pss::VerifyingKey::<D>::new(public_key.clone());
    let Ok(sig) = rsa::pss::Signature::try_from(signature) else {
        return false;
    };
    verifying_key.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::ObjectStore;
    use rsa::signature::Signer;
    use rsa::traits::PublicKeyParts;

    /// Regression test for the "verify with public-only key" fix: after a
    /// public-only import (SDK sends N and E via separate WriteRSAKey APDUs),
    /// `private_key_der` stays empty and N+E live only in `staged`. Verify and
    /// encrypt must still succeed by rebuilding `RsaPublicKey` from `staged`.
    fn make_public_only_keypair(pk: &RsaPublicKey, bits: u16) -> SecureObject {
        let mut staged = RsaComponents::default();
        staged.n = Some(pk.n().to_bytes_be());
        staged.e = Some(pk.e().to_bytes_be());
        SecureObject::RSAKeyPair {
            key_size_bits: bits,
            private_key_der: Vec::new(),
            staged,
        }
    }

    #[test]
    fn verify_works_with_public_only_key() {
        let sk = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let pk = RsaPublicKey::from(&sk);
        let obj = make_public_only_keypair(&pk, 1024);

        // Sign out-of-band with PKCS#1 v1.5 SHA-256 (algo 0x28).
        let data = b"public-only verify regression";
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(sk);
        let sig = signing_key.sign(data).to_vec();

        let resp = handle_rsa_verify(&obj, 0x28, data, &sig);
        assert_eq!(resp.sw, 0x9000, "verify returned {:04x}", resp.sw);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlvs[0].value, [0x01], "verify should report success");

        // Bad signature must still reach the RSA code path (no longer 0x6985)
        // and come back as verify=failure.
        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        let resp_bad = handle_rsa_verify(&obj, 0x28, data, &bad);
        assert_eq!(resp_bad.sw, 0x9000);
        let tlvs_bad = crate::tlv::parse_tlvs(&resp_bad.data).unwrap();
        assert_eq!(tlvs_bad[0].value, [0x02],
                   "corrupted sig should report verify=failure");
    }

    #[test]
    fn encrypt_works_with_public_only_key() {
        let sk = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let pk = RsaPublicKey::from(&sk);
        let obj_id = [0x30u8, 0x00, 0x00, 0xEE];
        let mut store = ObjectStore::new();
        store.insert(obj_id, make_public_only_keypair(&pk, 1024));

        // Craft an RSA-encrypt APDU (P1=RSA, P2=EncryptOneshot) with
        // TAG_1=key_id, TAG_2=algo(PKCS1v1.5=0x0A), TAG_3=plaintext.
        let plaintext = b"hello";
        let mut data = Vec::new();
        data.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        data.extend_from_slice(&Tlv::new(TAG_2, &[0x0A]).encode());
        data.extend_from_slice(&Tlv::new(TAG_3, plaintext).encode());
        let apdu = crate::apdu::ParsedApdu {
            cla: 0x80,
            ins: 0x03,
            p1: crate::apdu::P1_RSA,
            p2: crate::apdu::P2_ENCRYPT_ONESHOT,
            data,
            le: None,
        };

        let resp = handle_rsa_encrypt(&apdu, &mut store);
        assert_eq!(resp.sw, 0x9000, "encrypt returned {:04x}", resp.sw);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlvs[0].value.len(), 128,
                   "ciphertext should be one modulus (1024/8=128)");

        // Ensure it really encrypted for *this* key by decrypting with the
        // private half and checking the plaintext round-trips.
        let recovered = sk
            .decrypt(Pkcs1v15Encrypt, &tlvs[0].value)
            .expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    fn write_rsa_apdu(data: Vec<u8>) -> crate::apdu::ParsedApdu {
        crate::apdu::ParsedApdu {
            cla: 0x80,
            ins: crate::apdu::INS_WRITE,
            p1: crate::apdu::P1_RSA,
            p2: crate::apdu::P2_DEFAULT,
            data,
            le: None,
        }
    }

    #[test]
    fn se050e_refuses_rsa_keygen_and_import() {
        // Bench-verified on real SE050E silicon: keygen (size-only
        // APDU) refuses 0x6985; any APDU carrying key material
        // refuses 0x6A80. The SE051 personality still serves both.
        use crate::applet::AppletVersion;
        let mut store = ObjectStore::new();
        let obj_id = [0x7Fu8, 0x40, 0x00, 0x01];

        let mut keygen = Vec::new();
        keygen.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        keygen.extend_from_slice(&Tlv::new(TAG_2, &2048u16.to_be_bytes()).encode());
        let resp = handle_write_rsa_key(
            &write_rsa_apdu(keygen), &mut store, AppletVersion::V7_2_0E);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
        assert!(!store.exists(&obj_id));

        let mut import = Vec::new();
        import.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        import.extend_from_slice(&Tlv::new(TAG_2, &2048u16.to_be_bytes()).encode());
        import.extend_from_slice(&Tlv::new(TAG_RSA_PUB_EXP, &[0x01, 0x00, 0x01]).encode());
        import.extend_from_slice(&Tlv::new(TAG_RSA_PUB_MOD, &[0xB1; 256]).encode());
        let resp = handle_write_rsa_key(
            &write_rsa_apdu(import), &mut store, AppletVersion::V7_2_0E);
        assert_eq!(resp.sw, SW_WRONG_DATA);
        assert!(!store.exists(&obj_id));

        let mut keygen_1k = Vec::new();
        keygen_1k.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        keygen_1k.extend_from_slice(&Tlv::new(TAG_2, &1024u16.to_be_bytes()).encode());
        let resp = handle_write_rsa_key(
            &write_rsa_apdu(keygen_1k), &mut store, AppletVersion::V7_2_0);
        assert_eq!(resp.sw, 0x9000, "SE051 personality keeps RSA keygen");
        assert!(store.exists(&obj_id));
    }

    fn write_rsa_pub_apdu(data: Vec<u8>) -> crate::apdu::ParsedApdu {
        crate::apdu::ParsedApdu {
            cla: 0x80,
            ins: crate::apdu::INS_WRITE,
            p1: crate::apdu::P1_RSA | crate::apdu::P1_PUBLIC_KEY,
            p2: crate::apdu::P2_DEFAULT,
            data,
            le: None,
        }
    }

    #[test]
    fn se052f_rsa_restrictions() {
        // Bench-verified on real SE052F silicon: RSA is present (unlike
        // the SE050E) but 1024-bit generation refuses 0x6985, 2048-bit
        // generation works, and a public-key import refuses 0x6A80.
        use crate::applet::AppletVersion;
        let mut store = ObjectStore::new();
        let obj_id = [0x7Fu8, 0x40, 0x00, 0x02];

        let mut keygen_1k = Vec::new();
        keygen_1k.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        keygen_1k.extend_from_slice(&Tlv::new(TAG_2, &1024u16.to_be_bytes()).encode());
        let resp = handle_write_rsa_key(
            &write_rsa_apdu(keygen_1k), &mut store, AppletVersion::V7_2_22F);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED,
                   "SE052F refuses RSA below 2048 bits");
        assert!(!store.exists(&obj_id));

        let mut pub_import = Vec::new();
        pub_import.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        pub_import.extend_from_slice(&Tlv::new(TAG_2, &2048u16.to_be_bytes()).encode());
        pub_import.extend_from_slice(
            &Tlv::new(TAG_RSA_PUB_EXP, &[0x01, 0x00, 0x01]).encode());
        pub_import.extend_from_slice(&Tlv::new(TAG_RSA_PUB_MOD, &[0xB1; 256]).encode());
        let resp = handle_write_rsa_key(
            &write_rsa_pub_apdu(pub_import.clone()), &mut store,
            AppletVersion::V7_2_22F);
        assert_eq!(resp.sw, SW_WRONG_DATA,
                   "SE052F refuses RSA public key import");
        assert!(!store.exists(&obj_id));

        // The same import is served by the SE051 personality.
        let resp = handle_write_rsa_key(
            &write_rsa_pub_apdu(pub_import), &mut store, AppletVersion::V7_2_0);
        assert_eq!(resp.sw, 0x9000);
        assert!(store.exists(&obj_id));

        // 2048-bit generation works on the SE052F.
        let obj_2k = [0x7Fu8, 0x40, 0x00, 0x03];
        let mut keygen_2k = Vec::new();
        keygen_2k.extend_from_slice(&Tlv::new(TAG_1, &obj_2k).encode());
        keygen_2k.extend_from_slice(&Tlv::new(TAG_2, &2048u16.to_be_bytes()).encode());
        let resp = handle_write_rsa_key(
            &write_rsa_apdu(keygen_2k), &mut store, AppletVersion::V7_2_22F);
        assert_eq!(resp.sw, 0x9000, "SE052F generates 2048-bit RSA keys");
        assert!(store.exists(&obj_2k));
    }

    #[test]
    fn se052f_public_import_refused_without_key_part_bits() {
        // The key-part bits are the applet's own discriminator, but an
        // APDU carrying a whole public key means the same thing even
        // with those bits clear. Refusing only on the bits would let a
        // caller sidestep the SE052F restriction.
        use crate::applet::AppletVersion;
        let mut store = ObjectStore::new();
        let obj_id = [0x7Fu8, 0x40, 0x00, 0x04];

        let mut import = Vec::new();
        import.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
        import.extend_from_slice(&Tlv::new(TAG_2, &2048u16.to_be_bytes()).encode());
        import.extend_from_slice(
            &Tlv::new(TAG_RSA_PUB_EXP, &[0x01, 0x00, 0x01]).encode());
        import.extend_from_slice(&Tlv::new(TAG_RSA_PUB_MOD, &[0xB1; 256]).encode());

        // write_rsa_apdu leaves P1 as bare P1_RSA: no key-part bits.
        let resp = handle_write_rsa_key(
            &write_rsa_apdu(import.clone()), &mut store, AppletVersion::V7_2_22F);
        assert_eq!(resp.sw, SW_WRONG_DATA);
        assert!(!store.exists(&obj_id), "no public key object may be created");

        // Unaffected on a personality that allows public import.
        let resp = handle_write_rsa_key(
            &write_rsa_apdu(import), &mut store, AppletVersion::V7_2_0);
        assert_eq!(resp.sw, 0x9000);
        assert!(store.exists(&obj_id));
    }

    #[test]
    fn se052f_staged_private_import_still_works() {
        // The wolfCrypt port imports a private key as (E, D, N) across
        // three separate APDUs. None of them carries modulus and
        // exponent together without private material, so the SE052F
        // public-import refusal must not touch this flow -- refusing on
        // the mere presence of a public component would break it at the
        // very first APDU.
        use crate::applet::AppletVersion;
        let mut store = ObjectStore::new();
        let obj_id = [0x7Fu8, 0x40, 0x00, 0x05];

        let step = |tag: u8, value: &[u8]| {
            let mut data = Vec::new();
            data.extend_from_slice(&Tlv::new(TAG_1, &obj_id).encode());
            data.extend_from_slice(&Tlv::new(TAG_2, &2048u16.to_be_bytes()).encode());
            data.extend_from_slice(&Tlv::new(tag, value).encode());
            crate::apdu::ParsedApdu {
                cla: 0x80,
                ins: crate::apdu::INS_WRITE,
                p1: crate::apdu::P1_RSA | crate::apdu::P1_KEY_PAIR,
                p2: crate::apdu::P2_DEFAULT,
                data,
                le: None,
            }
        };

        for (name, tag, value) in [
            ("exponent", TAG_RSA_PUB_EXP, vec![0x01, 0x00, 0x01]),
            ("private exponent", TAG_RSA_PRIV, vec![0xC3; 256]),
            ("modulus", TAG_RSA_PUB_MOD, vec![0xB1; 256]),
        ] {
            let resp = handle_write_rsa_key(
                &step(tag, &value), &mut store, AppletVersion::V7_2_22F);
            assert_eq!(resp.sw, 0x9000, "SE052F staged import step: {}", name);
        }
        assert!(store.exists(&obj_id));
    }
}
