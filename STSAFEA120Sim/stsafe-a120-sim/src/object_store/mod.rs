/* mod.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STSAFEA120Sim.
 *
 * STSAFEA120Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STSAFEA120Sim is distributed in the hope that it will be useful,
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

use p256::{ecdsa::SigningKey, SecretKey};
use rand::rngs::OsRng;
use rand_core::RngCore;

pub use types::{CurveKind, DataZone, Device, EccSlot};

/// Default zone index for the device certificate. Matches the convention
/// `wolfSSL_STSAFE_LoadDeviceCertificate` uses (`certZone` defaults to 0).
pub const DEVICE_CERT_ZONE: u8 = 0;
/// Default slot for the persistent device private key.
pub const DEVICE_KEY_SLOT: u8 = 0;
/// Slot reserved for ephemeral ECDHE keys generated via Generate Key Pair.
pub const EPHEMERAL_KEY_SLOT: u8 = 0xFF;

/// In-memory store with optional JSON-file persistence.
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

    /// Build a fresh in-memory store with no on-disk persistence -- handy
    /// for tests and for the `STSAFE_SIM_FRESH` env override.
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

/// Build a freshly provisioned STSAFE-A120 device:
/// - Random 8-byte serial number.
/// - Slot 0: a P-256 device key whose public key is embedded in the
///   self-issued device certificate.
/// - Zone 0: a self-signed X.509-ish blob carrying the device public key.
///   The TLV parser in wolfSSL's stsafe.c only inspects the first 4 bytes
///   to derive the certificate length, so a minimal DER-shaped wrapper
///   (`SEQUENCE { ... }`) is sufficient for the smoke tests; the body of
///   the cert does not need to be a fully valid X.509 chain.
fn fresh_device() -> Device {
    let mut serial = [0u8; 8];
    OsRng.fill_bytes(&mut serial);

    let secret = SecretKey::random(&mut OsRng);
    let priv_bytes = secret.to_bytes().to_vec();

    let signing = SigningKey::from(&secret);
    let pub_point = signing.verifying_key().to_encoded_point(false);
    let pub_bytes = pub_point.as_bytes().to_vec(); // 0x04 || X || Y

    let cert = build_minimal_device_certificate(&serial, &pub_bytes);

    let mut ecc_slots = BTreeMap::new();
    ecc_slots.insert(
        DEVICE_KEY_SLOT,
        EccSlot {
            curve: CurveKind::NistP256,
            private_key: priv_bytes,
        },
    );

    let mut data_zones = BTreeMap::new();
    data_zones.insert(DEVICE_CERT_ZONE, DataZone { data: cert });

    Device {
        serial_number: serial,
        ecc_slots,
        data_zones,
    }
}

/// Build a minimal DER-shaped certificate blob that satisfies the
/// "first 4 bytes encode the length" assumption wolfSSL's
/// `SSL_STSAFE_LoadDeviceCertificate` uses (which is in turn forwarded to
/// `stse_get_device_certificate_size` -> reads bytes 2..4 and adds 4).
///
/// We do not attempt to produce a fully verifiable X.509 chain. Producing
/// one would require linking a real ASN.1 / X.509 library into the
/// simulator. The wolfCrypt smoke test path doesn't validate the cert
/// against a CA -- it just round-trips the bytes -- so a SEQUENCE
/// container with the public key inside is enough.
fn build_minimal_device_certificate(serial: &[u8; 8], pub_bytes: &[u8]) -> Vec<u8> {
    // Inner content: `0x80 8 serial_bytes... 0x81 65 pub_bytes...`
    // (context-specific-tagged TLVs, deterministic length encoding).
    let mut inner = Vec::new();
    inner.push(0x80); // [0] context-specific
    inner.push(serial.len() as u8);
    inner.extend_from_slice(serial);
    inner.push(0x81); // [1] context-specific
    inner.push(pub_bytes.len() as u8);
    inner.extend_from_slice(pub_bytes);

    // Wrap in DER SEQUENCE with 2-byte definite length:
    //   0x30  <len_hi> <len_lo>  <inner...>
    let mut cert = Vec::with_capacity(4 + inner.len());
    cert.push(0x30);
    cert.push(0x82); // long-form length, 2 bytes follow
    cert.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    cert.extend_from_slice(&inner);
    cert
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn fresh_store_has_device_key_and_cert() {
        let store = Store::fresh();
        assert!(store.device.ecc_slots.contains_key(&DEVICE_KEY_SLOT));
        let cert = &store
            .device
            .data_zones
            .get(&DEVICE_CERT_ZONE)
            .unwrap()
            .data;
        // SEQUENCE header
        assert_eq!(cert[0], 0x30);
        assert_eq!(cert[1], 0x82);
    }

    #[test]
    fn load_or_init_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sim_store.json");
        let store_a = Store::load_or_init(&path).unwrap();
        let serial = store_a.device.serial_number;
        drop(store_a);

        let store_b = Store::load_or_init(&path).unwrap();
        assert_eq!(store_b.device.serial_number, serial);
    }
}
