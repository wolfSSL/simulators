/* session.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of TROPIC01Sim.
 *
 * TROPIC01Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * TROPIC01Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// Noise_KK1_25519_AESGCM_SHA256 handshake + AES-GCM tunnel for the
/// TROPIC01 simulator.
///
/// Mirrors the host-side implementation in
/// `libtropic/src/libtropic_l3.c::lt_in__session_start` exactly, because
/// any deviation in transcript hashing or HKDF chaining produces a
/// different `kAUTH` and the host's tag verification fails.
///
/// Transcript chain (each step replaces `h`):
///   1. h = SHA256(protocol_name)         protocol_name = b"Noise_KK1_25519_AESGCM_SHA256\0\0\0" (32B)
///   2. h = SHA256(h || SHIPUB)           host static pubkey  (32B)
///   3. h = SHA256(h || STPUB)            chip static pubkey  (32B)
///   4. h = SHA256(h || EHPUB)            host ephemeral pubkey (32B)
///   5. h = SHA256(h || pkey_index)       1 byte
///   6. h = SHA256(h || ETPUB)            chip ephemeral pubkey (32B)
///
/// Key derivation (libtropic's custom HKDF, see `lt_hkdf.c`):
///   ck = protocol_name (32B)
///   ck    = HKDF(ck,    X25519(EHPRIV, ETPUB),    take output_1 only)
///   ck    = HKDF(ck33,  X25519(SHIPRIV, ETPUB),   take output_1 only)
///   ck, kAUTH = HKDF(ck33, X25519(EHPRIV, STPUB), take both)
///   kCMD, kRES = HKDF(ck33, "",                   take both)
///
/// where each "ck" stored as 33 bytes (32B HMAC output + trailing 0) so
/// the next call's salt is 33 bytes wide -- matches the libtropic buffer
/// shape literally (`output_1[33]`).
///
/// Auth tag: AES-GCM-Encrypt(key=kAUTH, iv=zeros[12], aad=h, plaintext="")
/// produces the 16-byte tag returned in the HANDSHAKE_RSP.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Static};

use crate::object_store::Device;

type HmacSha256 = Hmac<Sha256>;

const PROTOCOL_NAME: [u8; 32] = *b"Noise_KK1_25519_AESGCM_SHA256\0\0\0";
pub const HANDSHAKE_REQ_LEN: usize = 33; // EHPUB(32) + pkey_index(1)
pub const HANDSHAKE_RSP_LEN: usize = 48; // ETPUB(32) + tag(16)

/// AES-GCM keys + nonce counters for an open Secure Channel.
pub struct SessionKeys {
    pub k_cmd: [u8; 32],
    pub k_res: [u8; 32],
    pub nonce_cmd: [u8; 12],
    pub nonce_res: [u8; 12],
}

/// Per-connection volatile state.
#[derive(Default)]
pub struct Session {
    pub keys: Option<SessionKeys>,
}

/// Errors during HANDSHAKE_REQ processing. The L2 dispatcher maps these
/// to `status::HSK_ERR` -- the host then sees `LT_L2_HSK_ERR` and bails.
#[derive(Debug)]
pub enum HandshakeError {
    BadRequestLen,
    InvalidPairingSlot,
    UnauthorizedPairingSlot,
}

/// Errors when (un)wrapping an L3 ENCRYPTED_CMD packet.
#[derive(Debug)]
pub enum L3WrapError {
    /// L2 body too short to contain `[cmd_size: u16][ciphertext][tag: 16]`.
    Truncated,
    /// AES-GCM tag verification failed -- attacker, bit flip, nonce desync.
    BadTag,
    /// Per-direction nonce wrapped 2^32. Real silicon throws SESSION_INVALID.
    NonceOverflow,
}

fn step_nonce(nonce: &mut [u8; 12]) -> Result<(), L3WrapError> {
    // libtropic treats bytes 0..4 as a little-endian u32 counter and
    // leaves bytes 4..12 zero -- see `lt_l3_nonce_increase` in
    // `lt_l3_process.c`.
    let counter = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    if counter == u32::MAX {
        return Err(L3WrapError::NonceOverflow);
    }
    let next = counter + 1;
    nonce[0..4].copy_from_slice(&next.to_le_bytes());
    Ok(())
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_open(&self) -> bool {
        self.keys.is_some()
    }

    pub fn abort(&mut self) {
        self.keys = None;
    }

    /// Decrypt an ENCRYPTED_CMD L2 body into the L3 plaintext bytes
    /// (`[cmd_id (1B)][...fields...]`). The L2 body wire layout is
    /// `[cmd_size: u16 LE][ciphertext (cmd_size B)][tag (16B)]`.
    /// Increments `nonce_cmd` on success.
    pub fn unwrap_l3_request(&mut self, l2_body: &[u8]) -> Result<Vec<u8>, L3WrapError> {
        let keys = self.keys.as_mut().ok_or(L3WrapError::BadTag)?;
        if l2_body.len() < 2 + 16 {
            return Err(L3WrapError::Truncated);
        }
        let cmd_size = u16::from_le_bytes([l2_body[0], l2_body[1]]) as usize;
        if l2_body.len() != 2 + cmd_size + 16 {
            return Err(L3WrapError::Truncated);
        }
        let ct_and_tag = &l2_body[2..];
        let cipher = Aes256Gcm::new_from_slice(&keys.k_cmd).expect("32-byte key");
        let nonce: &Nonce<aes_gcm::aead::consts::U12> = (&keys.nonce_cmd).into();
        let plaintext = cipher
            .decrypt(nonce, Payload { msg: ct_and_tag, aad: &[] })
            .map_err(|_| L3WrapError::BadTag)?;
        step_nonce(&mut keys.nonce_cmd)?;
        Ok(plaintext)
    }

    /// Encrypt an L3 plaintext response (`[result (1B)][...fields...]`)
    /// into an ENCRYPTED_CMD L2 body. Increments `nonce_res` on success.
    pub fn wrap_l3_response(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, L3WrapError> {
        let keys = self.keys.as_mut().ok_or(L3WrapError::BadTag)?;
        let cipher = Aes256Gcm::new_from_slice(&keys.k_res).expect("32-byte key");
        let nonce: &Nonce<aes_gcm::aead::consts::U12> = (&keys.nonce_res).into();
        let ct_and_tag = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &[] })
            .expect("AES-GCM encrypt cannot fail with valid key/nonce");
        step_nonce(&mut keys.nonce_res)?;
        let res_size = plaintext.len() as u16;
        let mut wire = Vec::with_capacity(2 + ct_and_tag.len());
        wire.extend_from_slice(&res_size.to_le_bytes());
        wire.extend_from_slice(&ct_and_tag);
        Ok(wire)
    }

    /// Process a HANDSHAKE_REQ payload and emit the 48-byte HANDSHAKE_RSP
    /// body (`ETPUB(32) || tag(16)`). On success, opens a Secure Channel
    /// keyed by `kCMD`/`kRES` with both nonce counters reset to zero.
    pub fn handshake(
        &mut self,
        device: &Device,
        request: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if request.len() != HANDSHAKE_REQ_LEN {
            return Err(HandshakeError::BadRequestLen);
        }
        let ehpub: [u8; 32] = request[..32].try_into().unwrap();
        let pkey_index = request[32];

        let pairing_slot = device
            .pairing_slots
            .get(&pkey_index)
            .ok_or(HandshakeError::InvalidPairingSlot)?;
        if !pairing_slot.is_valid {
            return Err(HandshakeError::UnauthorizedPairingSlot);
        }
        let shipub = pairing_slot.public_key;

        // Generate the chip's ephemeral X25519 keypair (ETPRIV/ETPUB).
        let mut etpriv_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut etpriv_bytes);
        let etpriv = X25519Static::from(etpriv_bytes);
        let etpub = X25519Public::from(&etpriv).to_bytes();

        // Transcript hash: h = SHA256(protocol_name || SHIPUB || STPUB || EHPUB || pkey_index || ETPUB),
        // applied iteratively (each new piece prepends the prior digest).
        let h0 = sha256(&PROTOCOL_NAME);
        let h1 = sha256_concat(&h0, &shipub);
        let h2 = sha256_concat(&h1, &device.st_pub);
        let h3 = sha256_concat(&h2, &ehpub);
        let h4 = sha256_concat(&h3, &[pkey_index]);
        let h = sha256_concat(&h4, &etpub);

        // ECDH triple. Note the chip plays the same three X25519 ops as
        // the host -- it computes the same shared secrets from the other
        // direction:
        //   ss1 = X25519(ETPRIV, EHPUB)  ==  X25519(EHPRIV, ETPUB)
        //   ss2 = X25519(ETPRIV, SHIPUB) ==  X25519(SHIPRIV, ETPUB)
        //   ss3 = X25519(STPRIV, EHPUB)  ==  X25519(EHPRIV, STPUB)
        let ehpub_pk = X25519Public::from(ehpub);
        let shipub_pk = X25519Public::from(shipub);
        let stpriv = X25519Static::from(device.st_priv);

        let ss1 = etpriv.diffie_hellman(&ehpub_pk).to_bytes();
        let ss2 = etpriv.diffie_hellman(&shipub_pk).to_bytes();
        let ss3 = stpriv.diffie_hellman(&ehpub_pk).to_bytes();

        // libtropic-style HKDF chain.
        let mut ck33 = [0u8; 33];
        ck33[..32].copy_from_slice(&PROTOCOL_NAME);
        // After step 0 the salt is 32 bytes (PROTOCOL_NAME). The
        // subsequent steps use a 33-byte salt -- the prior `output_1`
        // padded with one trailing zero -- to mirror the
        // `output_1[33] = {0}` buffer libtropic passes.
        let (out1_a, _) = lt_hkdf(&PROTOCOL_NAME, &ss1);
        ck33[..32].copy_from_slice(&out1_a);
        let (out1_b, _) = lt_hkdf(&ck33, &ss2);
        ck33[..32].copy_from_slice(&out1_b);
        let (out1_c, k_auth) = lt_hkdf(&ck33, &ss3);
        ck33[..32].copy_from_slice(&out1_c);
        let (k_cmd, k_res) = lt_hkdf(&ck33, b"");

        // Auth tag: AES-256-GCM seal with kAUTH, IV = 12 zero bytes,
        // AAD = h, plaintext empty. The 16-byte tag is the only output.
        let tag = aes_gcm_seal_tag(&k_auth, &[0u8; 12], &h);

        self.keys = Some(SessionKeys {
            k_cmd,
            k_res,
            nonce_cmd: [0u8; 12],
            nonce_res: [0u8; 12],
        });

        let mut response = Vec::with_capacity(HANDSHAKE_RSP_LEN);
        response.extend_from_slice(&etpub);
        response.extend_from_slice(&tag);
        Ok(response)
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn sha256_concat(prev: &[u8; 32], extra: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(extra);
    h.finalize().into()
}

/// Reproduces `lt_hkdf` from `libtropic/src/lt_hkdf.c`:
///   tmp     = HMAC-SHA256(key=salt, msg=ikm)
///   output1 = HMAC-SHA256(key=tmp,  msg=[0x01])
///   output2 = HMAC-SHA256(key=tmp,  msg=output1 || [0x02])
fn lt_hkdf(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    let tmp: [u8; 32] = mac.finalize().into_bytes().into();

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&tmp).unwrap();
    mac.update(&[0x01]);
    let out1: [u8; 32] = mac.finalize().into_bytes().into();

    let mut helper = [0u8; 33];
    helper[..32].copy_from_slice(&out1);
    helper[32] = 0x02;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&tmp).unwrap();
    mac.update(&helper);
    let out2: [u8; 32] = mac.finalize().into_bytes().into();

    (out1, out2)
}

fn aes_gcm_seal_tag(key: &[u8; 32], iv: &[u8; 12], aad: &[u8]) -> [u8; 16] {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte AES key");
    let nonce: &Nonce<aes_gcm::aead::consts::U12> = (iv).into();
    let ct = cipher
        .encrypt(nonce, Payload { msg: &[], aad })
        .expect("AES-GCM seal of empty plaintext cannot fail");
    // Empty plaintext -> output is just the 16-byte tag.
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ct);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::{
        default_host_pairing_priv, default_host_pairing_pub, Store,
    };

    /// End-to-end check: drive the handshake from the host side using the
    /// engineering-sample SHIPRIV/SHIPUB and verify the chip's auth tag.
    #[test]
    fn handshake_round_trip_is_authenticated() {
        let store = Store::fresh();
        let device = &store.device;

        // Host's ephemeral keypair.
        let mut ehpriv_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut ehpriv_bytes);
        let ehpriv = X25519Static::from(ehpriv_bytes);
        let ehpub = X25519Public::from(&ehpriv).to_bytes();

        // Send HANDSHAKE_REQ to the simulator.
        let mut req = Vec::with_capacity(HANDSHAKE_REQ_LEN);
        req.extend_from_slice(&ehpub);
        req.push(0u8); // pkey_index
        let mut session = Session::new();
        let rsp = session.handshake(device, &req).expect("handshake");
        assert_eq!(rsp.len(), HANDSHAKE_RSP_LEN);
        assert!(session.is_open());

        // Host-side verification of the auth tag.
        let etpub: [u8; 32] = rsp[..32].try_into().unwrap();
        let tag: [u8; 16] = rsp[32..48].try_into().unwrap();

        let shipub = default_host_pairing_pub();
        let shipriv_bytes = default_host_pairing_priv();
        let shipriv = X25519Static::from(shipriv_bytes);

        let h0 = sha256(&PROTOCOL_NAME);
        let h1 = sha256_concat(&h0, &shipub);
        let h2 = sha256_concat(&h1, &device.st_pub);
        let h3 = sha256_concat(&h2, &ehpub);
        let h4 = sha256_concat(&h3, &[0u8]);
        let h = sha256_concat(&h4, &etpub);

        let etpub_pk = X25519Public::from(etpub);
        let stpub_pk = X25519Public::from(device.st_pub);
        let ss1 = ehpriv.diffie_hellman(&etpub_pk).to_bytes();
        let ss2 = shipriv.diffie_hellman(&etpub_pk).to_bytes();
        let ss3 = ehpriv.diffie_hellman(&stpub_pk).to_bytes();

        let mut ck33 = [0u8; 33];
        ck33[..32].copy_from_slice(&PROTOCOL_NAME);
        let (out_a, _) = lt_hkdf(&PROTOCOL_NAME, &ss1);
        ck33[..32].copy_from_slice(&out_a);
        let (out_b, _) = lt_hkdf(&ck33, &ss2);
        ck33[..32].copy_from_slice(&out_b);
        let (out_c, host_kauth) = lt_hkdf(&ck33, &ss3);
        ck33[..32].copy_from_slice(&out_c);
        let (host_kcmd, host_kres) = lt_hkdf(&ck33, b"");

        // Verify the chip's tag using AES-GCM open semantics.
        let cipher = Aes256Gcm::new_from_slice(&host_kauth).unwrap();
        let zero_iv = [0u8; 12];
        let nonce: &Nonce<aes_gcm::aead::consts::U12> = (&zero_iv).into();
        // Ciphertext is just the tag (no plaintext bytes).
        let result = cipher.decrypt(nonce, Payload { msg: &tag, aad: &h });
        assert!(result.is_ok(), "host-side tag verification failed");

        // Confirm both sides derived identical traffic keys.
        let chip_keys = session.keys.as_ref().unwrap();
        assert_eq!(host_kcmd, chip_keys.k_cmd);
        assert_eq!(host_kres, chip_keys.k_res);
    }

    #[test]
    fn handshake_rejects_invalid_pairing_slot() {
        let store = Store::fresh();
        let mut session = Session::new();
        let mut req = vec![0u8; HANDSHAKE_REQ_LEN];
        req[32] = 5; // pkey_index out of range
        let res = session.handshake(&store.device, &req);
        assert!(matches!(res, Err(HandshakeError::InvalidPairingSlot)));
        assert!(!session.is_open());
    }

    #[test]
    fn handshake_rejects_bad_request_len() {
        let store = Store::fresh();
        let mut session = Session::new();
        let res = session.handshake(&store.device, &[0u8; 10]);
        assert!(matches!(res, Err(HandshakeError::BadRequestLen)));
    }

    #[test]
    fn lt_hkdf_two_outputs_match_libtropic_shape() {
        // Smoke test: lt_hkdf should produce 32B outputs and the second
        // output should differ from the first (otherwise the helper byte
        // [0x02] suffix isn't being applied).
        let (a, b) = lt_hkdf(b"saltysalt", b"some input keying material");
        assert_ne!(a, b);
    }
}
