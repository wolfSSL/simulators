/* mod.rs
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

pub mod types;

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand_core::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Static};

pub use types::{CurveKind, Device, EccSlot, KeyOrigin, PairingSlot, RMemSlot};

/// Default pairing-key slot used by the wolfSSL port (`PAIRING_KEY_SLOT_INDEX_0`).
pub const DEFAULT_PAIRING_SLOT: u8 = 0;

/// In-memory store with optional JSON-file persistence. Mirrors the
/// `Store` shape used by the other simulators in this repo.
pub struct Store {
    pub device: Device,
    path: Option<PathBuf>,
}

impl Store {
    /// Load from `path` if it exists, otherwise create a freshly provisioned
    /// store and persist it back to `path`.
    pub fn load_or_init(path: &Path) -> io::Result<Self> {
        if path.exists() {
            let bytes = fs::read(path)?;
            let device: Device = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(Self {
                device,
                path: Some(path.to_path_buf()),
            });
        }
        let store = Self {
            device: fresh_device(),
            path: Some(path.to_path_buf()),
        };
        store.persist()?;
        Ok(store)
    }

    /// Build a freshly provisioned store with no on-disk persistence.
    pub fn fresh() -> Self {
        Self {
            device: fresh_device(),
            path: None,
        }
    }

    pub fn persist(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec_pretty(&self.device)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, bytes)
    }
}

/// Build a freshly provisioned TROPIC01 simulator device:
/// - Random 12-byte chip ID.
/// - Random X25519 static keypair (STPRIV/STPUB).
/// - A minimal X.509-shaped certificate carrying STPUB at the X25519
///   subject-public-key offset libtropic's ASN.1 helper looks for.
/// - Pairing slot 0 holds the host pairing pubkey from `default_host_pairing_pub()`.
///   The matching host private key is `default_host_pairing_priv()`. These
///   are the dev fixtures the wolfSSL test app feeds via `Tropic01_SetPairingKeys`.
/// - R-memory slots 0..=3 pre-loaded with the AES/Ed25519 fixtures the
///   wolfSSL crypto callback expects (see tropic01.h:57-76).
/// - No ECC slots populated; wolfSSL's keygen test populates ECC slot 1
///   on-the-fly.
fn fresh_device() -> Device {
    let mut chip_id = [0u8; 12];
    OsRng.fill_bytes(&mut chip_id);

    let st_priv_bytes = {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        b
    };
    let st_secret = X25519Static::from(st_priv_bytes);
    let st_pub_bytes = X25519Public::from(&st_secret).to_bytes();

    let cert_store = build_minimal_cert_store(&st_pub_bytes);

    let mut pairing_slots = BTreeMap::new();
    pairing_slots.insert(
        DEFAULT_PAIRING_SLOT,
        PairingSlot {
            public_key: default_host_pairing_pub(),
            is_valid: true,
        },
    );

    let mut r_mem_slots = BTreeMap::new();
    r_mem_slots.insert(0, RMemSlot { data: default_aes_key().to_vec() });
    r_mem_slots.insert(1, RMemSlot { data: default_aes_iv().to_vec() });
    r_mem_slots.insert(2, RMemSlot { data: default_ed25519_pub().to_vec() });
    r_mem_slots.insert(3, RMemSlot { data: default_ed25519_priv().to_vec() });

    Device {
        chip_id,
        st_priv: st_priv_bytes,
        st_pub: st_pub_bytes,
        cert_store,
        pairing_slots,
        ecc_slots: BTreeMap::new(),
        r_mem_slots,
    }
}

/// Sizes of each cert in the cert-store fixture, in order
/// `[device, xxxx, tropic01, root]`. Each entry must be > 128 bytes so
/// `lt_get_info_cert_store`'s "at most one trailing chunk" assumption
/// holds. The device cert is 256B (so the X25519 SPKI fits comfortably
/// with room for an outer SEQUENCE wrapper); the others are 128B-aligned
/// padding because nothing inspects them.
const CERT_LENS: [usize; 4] = [256, 128, 128, 128];

/// Header length: version (1) + num_certs (1) + 4 BE u16 cert lengths (8) = 10 B.
const CERT_STORE_HEADER_LEN: usize = 10;

/// Total cert-store blob length (header + concatenated certs). Padded up
/// to the next 128B boundary so chunked reads always return a full
/// 128-byte chunk -- libtropic's helper checks `rsp_len == 128` per
/// chunk and would error out on a short final chunk.
pub fn cert_store_blob_len() -> usize {
    let total = CERT_STORE_HEADER_LEN + CERT_LENS.iter().sum::<usize>();
    total.div_ceil(128) * 128
}

/// Build the 4-cert cert-store blob libtropic reads via
/// `GET_INFO(X509_CERTIFICATE)`. Layout (matches the parser in
/// `libtropic/src/libtropic.c::lt_get_info_cert_store`):
///
///   [0]      version (1)
///   [1]      num_certs (4)
///   [2..10]  4 BE u16 cert lengths
///   [10..]   <cert0> <cert1> <cert2> <cert3>
///   <pad to 128B chunk boundary>
///
/// Cert 0 is a 256-byte DER blob containing an X25519 SPKI:
///   30 82 00 FC                          SEQUENCE (long-form, len 252)
///     30 05 06 03 2B 65 6E               AlgorithmIdentifier (X25519 OID)
///     03 21 00 <32 STPUB bytes>          BIT STRING (33 B: unused-bits=0 + key)
///     <padding zero bytes to fill 256B>
///
/// libtropic's recursive ASN.1 parser walks the outer SEQUENCE, finds
/// the X25519 OID (1.3.101.110), captures the next BIT STRING, and
/// crops the leading "unused-bits" byte to recover the 32-byte STPUB.
/// Padding is consumed silently: trailing 0x00 bytes parse as
/// zero-length tags that the parser drops without error.
fn build_minimal_cert_store(st_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; cert_store_blob_len()];
    out[0] = 1; // version
    out[1] = 4; // num_certs
    for (i, &len) in CERT_LENS.iter().enumerate() {
        let lo = 2 + i * 2;
        out[lo..lo + 2].copy_from_slice(&(len as u16).to_be_bytes());
    }

    // Place cert 0 starting at byte 10.
    let mut p = CERT_STORE_HEADER_LEN;
    let device_cert = build_device_cert(st_pub, CERT_LENS[0]);
    out[p..p + device_cert.len()].copy_from_slice(&device_cert);
    p += CERT_LENS[0];

    // Certs 1..3: 128 bytes each. They're never inspected by libtropic
    // beyond a memcpy into the host buffer, so any DER-shaped padding
    // works. We emit a SEQUENCE wrapper of length 125 with zero padding
    // inside so an offline DER inspector doesn't get confused.
    for &len in &CERT_LENS[1..] {
        let inner_len = len - 3;
        out[p] = 0x30;
        out[p + 1] = 0x81;
        out[p + 2] = inner_len as u8;
        // bytes p+3..p+len already zero
        p += len;
    }

    out
}

fn build_device_cert(st_pub: &[u8; 32], total_len: usize) -> Vec<u8> {
    // Outer SEQUENCE header: 30 82 <len_hi> <len_lo>  -- 4 bytes.
    // Inner length = total_len - 4.
    assert!(total_len >= 4 + 44 && total_len <= 0xFFFF + 4);
    let inner_len = (total_len - 4) as u16;
    let mut out = vec![0u8; total_len];
    out[0] = 0x30;
    out[1] = 0x82;
    out[2..4].copy_from_slice(&inner_len.to_be_bytes());

    // Then the SPKI right after the header.
    let spki = [
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, // AlgorithmIdentifier (X25519)
        0x03, 0x21, 0x00, // BIT STRING tag, length 33, unused-bits=0
    ];
    let spki_start = 4;
    out[spki_start..spki_start + spki.len()].copy_from_slice(&spki);
    out[spki_start + spki.len()..spki_start + spki.len() + 32].copy_from_slice(st_pub);
    // Remainder is zero padding, which the ASN.1 parser absorbs as
    // sequences of (tag=0x00, length=0).
    out
}

/// `sh0priv_eng_sample` from `libtropic/src/libtropic_default_sh0_keys.c`.
/// libtropic exports this constant as the host pairing private key for
/// engineering (pre-production) TROPIC01 samples in slot 0; using the same
/// bytes here means the wolfSSL test app and any libtropic client can
/// authenticate against the simulator with no extra setup.
pub const DEFAULT_HOST_PAIRING_PRIV: [u8; 32] = [
    0xd0, 0x99, 0x92, 0xb1, 0xf1, 0x7a, 0xbc, 0x4d, 0xb9, 0x37, 0x17, 0x68, 0xa2, 0x7d, 0xa0, 0x5b,
    0x18, 0xfa, 0xb8, 0x56, 0x13, 0xa7, 0x84, 0x2c, 0xa6, 0x4c, 0x79, 0x10, 0xf2, 0x2e, 0x71, 0x6b,
];

/// `sh0pub_eng_sample` from `libtropic/src/libtropic_default_sh0_keys.c`.
/// Matches the X25519 public key derived from `DEFAULT_HOST_PAIRING_PRIV`.
pub const DEFAULT_HOST_PAIRING_PUB: [u8; 32] = [
    0xe7, 0xf7, 0x35, 0xba, 0x19, 0xa3, 0x3f, 0xd6, 0x73, 0x23, 0xab, 0x37, 0x26, 0x2d, 0xe5, 0x36,
    0x08, 0xca, 0x57, 0x85, 0x76, 0x53, 0x43, 0x52, 0xe1, 0x8f, 0x64, 0xe6, 0x13, 0xd3, 0x8d, 0x54,
];

pub fn default_host_pairing_priv() -> [u8; 32] {
    DEFAULT_HOST_PAIRING_PRIV
}

pub fn default_host_pairing_pub() -> [u8; 32] {
    DEFAULT_HOST_PAIRING_PUB
}

pub fn default_aes_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x11);
    }
    k
}

pub fn default_aes_iv() -> [u8; 32] {
    let mut iv = [0u8; 32];
    for (i, b) in iv.iter_mut().enumerate() {
        *b = i as u8;
    }
    iv
}

pub fn default_ed25519_priv() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = 0x40 | (i as u8 & 0x3F);
    }
    s
}

pub fn default_ed25519_pub() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(&default_ed25519_priv())
        .verifying_key()
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fresh_store_has_chip_identity() {
        let store = Store::fresh();
        assert_ne!(store.device.st_pub, [0u8; 32]);
        // [version=1][num_certs=4][4x BE u16 cert lengths starting at byte 2]
        assert_eq!(store.device.cert_store[0], 1);
        assert_eq!(store.device.cert_store[1], 4);
        // Device cert begins at byte 10 with `30 82 <len_hi> <len_lo>`
        // and STPUB lands 14 bytes in (header + SPKI prefix).
        assert_eq!(store.device.cert_store[10], 0x30);
        let stpub_offset = 10 + 4 + 10; // header + outer hdr + SPKI prefix
        assert_eq!(
            &store.device.cert_store[stpub_offset..stpub_offset + 32],
            &store.device.st_pub
        );
    }

    #[test]
    fn cert_store_blob_is_chunk_aligned() {
        let store = Store::fresh();
        assert_eq!(store.device.cert_store.len() % 128, 0);
        assert_eq!(store.device.cert_store.len(), 768); // 6 chunks of 128
    }

    #[test]
    fn fresh_store_has_default_pairing_slot() {
        let store = Store::fresh();
        let slot = store.device.pairing_slots.get(&0).unwrap();
        assert!(slot.is_valid);
        assert_eq!(slot.public_key, default_host_pairing_pub());
    }

    #[test]
    fn engineering_sample_keys_are_consistent_pair() {
        // Verify the sh0priv/sh0pub bytes from libtropic actually form a
        // valid X25519 pair under x25519-dalek's clamping.
        let secret = X25519Static::from(DEFAULT_HOST_PAIRING_PRIV);
        let derived = X25519Public::from(&secret).to_bytes();
        assert_eq!(derived, DEFAULT_HOST_PAIRING_PUB);
    }

    #[test]
    fn fresh_store_has_r_mem_fixtures() {
        let store = Store::fresh();
        assert_eq!(store.device.r_mem_slots.get(&0).unwrap().data.len(), 32);
        assert_eq!(store.device.r_mem_slots.get(&3).unwrap().data.len(), 32);
        assert_eq!(
            store.device.r_mem_slots.get(&2).unwrap().data,
            default_ed25519_pub().to_vec()
        );
    }

    #[test]
    fn load_or_init_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tropic_store.json");
        let store_a = Store::load_or_init(&path).unwrap();
        let chip_id = store_a.device.chip_id;
        drop(store_a);
        let store_b = Store::load_or_init(&path).unwrap();
        assert_eq!(store_b.device.chip_id, chip_id);
    }
}
