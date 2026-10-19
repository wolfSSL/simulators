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

use crate::certs;
use crate::personality::Personality;

pub use types::{
    CurveKind, Device, EccSlot, KeyOrigin, PairingSlot, PairingState, CONFIG_REGISTERS,
    STORE_FORMAT_VERSION,
};

/// `lt_sh0priv_eng_sample` from libtropic `src/libtropic_default_sh0_keys.c`.
pub const LT_SH0PRIV_ENG_SAMPLE: [u8; 32] = [
    0xd0, 0x99, 0x92, 0xb1, 0xf1, 0x7a, 0xbc, 0x4d, 0xb9, 0x37, 0x17, 0x68, 0xa2, 0x7d, 0xa0, 0x5b,
    0x18, 0xfa, 0xb8, 0x56, 0x13, 0xa7, 0x84, 0x2c, 0xa6, 0x4c, 0x79, 0x10, 0xf2, 0x2e, 0x71, 0x6b,
];

/// `lt_sh0pub_eng_sample`: pairing slot 0 of engineering-sample parts.
pub const LT_SH0PUB_ENG_SAMPLE: [u8; 32] = [
    0xe7, 0xf7, 0x35, 0xba, 0x19, 0xa3, 0x3f, 0xd6, 0x73, 0x23, 0xab, 0x37, 0x26, 0x2d, 0xe5, 0x36,
    0x08, 0xca, 0x57, 0x85, 0x76, 0x53, 0x43, 0x52, 0xe1, 0x8f, 0x64, 0xe6, 0x13, 0xd3, 0x8d, 0x54,
];

/// `lt_sh0priv_prod0`.
pub const LT_SH0PRIV_PROD0: [u8; 32] = [
    0x28, 0x3f, 0x5a, 0x0f, 0xfc, 0x41, 0xcf, 0x50, 0x98, 0xa8, 0xe1, 0x7d, 0xb6, 0x37, 0x2c, 0x3c,
    0xaa, 0xd1, 0xee, 0xee, 0xdf, 0x0f, 0x75, 0xbc, 0x3f, 0xbf, 0xcd, 0x9c, 0xab, 0x3d, 0xe9, 0x72,
];

/// `lt_sh0pub_prod0`: pairing slot 0 of production parts.
pub const LT_SH0PUB_PROD0: [u8; 32] = [
    0xf9, 0x75, 0xeb, 0x3c, 0x2f, 0xd7, 0x90, 0xc9, 0x6f, 0x29, 0x4f, 0x15, 0x57, 0xa5, 0x03, 0x17,
    0x80, 0xc9, 0xaa, 0xfa, 0x14, 0x0d, 0xa2, 0x8f, 0x55, 0xe7, 0x51, 0x57, 0x37, 0xb2, 0x50, 0x2c,
];

/// How a fresh device is provisioned.
#[derive(Clone, Copy, Debug, Default)]
pub struct Provisioning {
    pub personality: Personality,
    /// Pre-load R-Memory slots 0..=3 with the fixtures wolfSSL's TROPIC01
    /// port (`wolfcrypt/src/port/tropicsquare/tropic01.c`) reads from its
    /// hardcoded slot map. A real chip ships with empty R-Memory.
    pub wolfssl_fixtures: bool,
}

pub struct Store {
    pub device: Device,
    path: Option<PathBuf>,
}

impl Store {
    /// Load the device from `path`, or provision a new one there.
    pub fn load_or_init(path: &Path, prov: Provisioning) -> io::Result<Self> {
        if path.exists() {
            let bytes = fs::read(path)?;
            let device: Device = serde_json::from_slice(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: {e} (stores from older simulator versions are not \
                         compatible; set TROPIC01_SIM_FRESH=1 to reprovision)",
                        path.display()
                    ),
                )
            })?;
            if device.format_version != STORE_FORMAT_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: store format {} is not {STORE_FORMAT_VERSION}; set \
                         TROPIC01_SIM_FRESH=1 to reprovision",
                        path.display(),
                        device.format_version
                    ),
                ));
            }
            return Ok(Self {
                device,
                path: Some(path.to_path_buf()),
            });
        }
        let store = Self {
            device: provision(prov),
            path: Some(path.to_path_buf()),
        };
        store.persist()?;
        Ok(store)
    }

    /// A freshly provisioned device that is never written to disk.
    pub fn fresh() -> Self {
        Self::fresh_with(Provisioning::default())
    }

    pub fn fresh_with(prov: Provisioning) -> Self {
        Self {
            device: provision(prov),
            path: None,
        }
    }

    /// Provision a new device and persist it to `path`, replacing whatever
    /// was there.
    pub fn create(path: &Path, prov: Provisioning) -> io::Result<Self> {
        let store = Self {
            device: provision(prov),
            path: Some(path.to_path_buf()),
        };
        store.persist()?;
        Ok(store)
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

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

fn provision(prov: Provisioning) -> Device {
    let p = prov.personality;

    let mut serial = [0u8; 8];
    OsRng.fill_bytes(&mut serial);

    let st_priv = random32();
    let st_pub = X25519Public::from(&X25519Static::from(st_priv)).to_bytes();
    let cert_store = certs::build_cert_store(&st_pub, &serial);

    let mut pairing_slots = BTreeMap::new();
    pairing_slots.insert(
        0,
        PairingSlot {
            public_key: p.default_sh0_pub(),
            state: PairingState::Written,
        },
    );

    let mut r_config = vec![0xffff_ffffu32; CONFIG_REGISTERS];
    r_config[0] = p.default_r_config_start_up();
    let mut i_config = vec![0xffff_ffffu32; CONFIG_REGISTERS];
    i_config[0] = p.default_i_config_start_up();

    let mut r_mem_slots = BTreeMap::new();
    if prov.wolfssl_fixtures {
        r_mem_slots.insert(0, wolfssl_fixture_aes_key().to_vec());
        r_mem_slots.insert(1, wolfssl_fixture_aes_iv().to_vec());
        r_mem_slots.insert(2, wolfssl_fixture_ed25519_pub().to_vec());
        r_mem_slots.insert(3, wolfssl_fixture_ed25519_priv().to_vec());
    }

    Device {
        format_version: STORE_FORMAT_VERSION,
        personality: p,
        chip_id: p.chip_id(&serial),
        st_priv,
        st_pub,
        cert_store,
        pairing_slots,
        r_config,
        i_config,
        ecc_slots: BTreeMap::new(),
        r_mem_slots,
        mcounters: BTreeMap::new(),
        macandd_slots: BTreeMap::new(),
        macandd_keys: [random32(), random32()],
    }
}

/// AES-256 key fixture for wolfSSL's TROPIC01 port (R-Memory slot 0).
pub fn wolfssl_fixture_aes_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x11);
    }
    k
}

/// AES IV fixture (R-Memory slot 1).
pub fn wolfssl_fixture_aes_iv() -> [u8; 32] {
    let mut iv = [0u8; 32];
    for (i, b) in iv.iter_mut().enumerate() {
        *b = i as u8;
    }
    iv
}

/// Ed25519 private key fixture (R-Memory slot 3).
pub fn wolfssl_fixture_ed25519_priv() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = 0x40 | (i as u8 & 0x3F);
    }
    s
}

/// Ed25519 public key fixture matching the private key (R-Memory slot 2).
pub fn wolfssl_fixture_ed25519_pub() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(&wolfssl_fixture_ed25519_priv())
        .verifying_key()
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fresh_store_matches_a_blank_chip() {
        let store = Store::fresh();
        let d = &store.device;
        assert_eq!(d.personality, Personality::Es012);
        assert_eq!(d.chip_id.len(), 128);
        assert_ne!(d.st_pub, [0u8; 32]);
        assert_eq!(d.pairing_slots.len(), 1);
        assert_eq!(d.pairing_slots[&0].public_key, LT_SH0PUB_ENG_SAMPLE);
        assert!(d.r_mem_slots.is_empty());
        assert!(d.ecc_slots.is_empty());
        assert!(d.mcounters.is_empty());
        assert_eq!(d.r_config[0], 0xffff_ffef);
        assert_eq!(d.effective_config()[0x100 / 4], 0xffff_ffff);
    }

    #[test]
    fn production_personality_uses_prod0_key() {
        let store = Store::fresh_with(Provisioning {
            personality: Personality::Fw220,
            wolfssl_fixtures: false,
        });
        assert_eq!(store.device.pairing_slots[&0].public_key, LT_SH0PUB_PROD0);
    }

    #[test]
    fn updated_es_part_has_the_erratum_fix() {
        let store = Store::fresh_with(Provisioning {
            personality: Personality::Es220,
            wolfssl_fixtures: false,
        });
        let d = &store.device;
        assert_eq!(d.pairing_slots[&0].public_key, LT_SH0PUB_ENG_SAMPLE);
        assert_eq!(d.r_config[0], 0xffff_ffeb);
        assert_eq!(d.i_config[0], 0xffff_fffb);
    }

    #[test]
    fn wolfssl_fixtures_are_opt_in() {
        let store = Store::fresh_with(Provisioning {
            personality: Personality::Es012,
            wolfssl_fixtures: true,
        });
        assert_eq!(store.device.r_mem_slots.len(), 4);
        assert_eq!(
            store.device.r_mem_slots[&0],
            wolfssl_fixture_aes_key().to_vec()
        );
    }

    #[test]
    fn persist_and_reload_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.json");
        let a = Store::load_or_init(&path, Provisioning::default()).unwrap();
        let b = Store::load_or_init(&path, Provisioning::default()).unwrap();
        assert_eq!(a.device.st_pub, b.device.st_pub);
        assert_eq!(a.device.chip_id, b.device.chip_id);
        assert_eq!(a.device.cert_store, b.device.cert_store);
    }

    #[test]
    fn stale_store_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.json");
        fs::write(&path, b"{\"chip_id\": []}").unwrap();
        assert!(Store::load_or_init(&path, Provisioning::default()).is_err());
    }
}
