/* mod.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of ATECC608Sim.
 *
 * ATECC608Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * ATECC608Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

pub mod types;

pub use types::{Device, SlotData, zone, CONFIG_SIZE, NUM_SLOTS, OTP_SIZE, SLOT_SIZE};

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Build a Device with a wolfSSL-friendly default configuration.
///
/// Layout (following Microchip TrustFLEX-style provisioning):
/// - Slots 0..=7 : P-256 ECC private key slots, slot-unlocked so wolfSSL can
///   GenKey into them even after the config/data zones are globally locked.
/// - Slots 8..=15 : generic data slots.
/// - Serial number populated at config[0..4] and config[8..13].
/// - Both Config and Data zones ship locked so wolfSSL's `atcab_is_locked()`
///   checks pass out of the box.
pub fn default_device() -> Device {
    let mut config = [0u8; CONFIG_SIZE];

    // Serial number: SE/SE050Sim-style fixed identity.
    //  SN[0..2]   = config[0..2]    (fixed 0x01 0x23 per datasheet)
    //  Reserved   = config[2..4]
    //  SN[3..8]   = config[8..13]
    config[0] = 0x01;
    config[1] = 0x23;
    config[2] = 0x00;
    config[3] = 0x00;
    // Revision number at config[4..8]; 0x00 00 60 02 marks an ATECC608A.
    config[4] = 0x00;
    config[5] = 0x00;
    config[6] = 0x60;
    config[7] = 0x02;
    config[8] = 0xEE; // SN[3]
    config[9] = 0xCC;
    config[10] = 0xBB;
    config[11] = 0xAA;
    config[12] = 0x99;
    config[13] = 0x88;
    config[14] = 0xEE; // SN[8] — fixed 0xEE per datasheet
    config[15] = 0x01; // AES_Enable / RFU

    // I2C_Address at config[16]: default 0xC0 (which is 0x60 << 1).
    config[16] = 0xC0;

    // SlotConfig at config[20..52], 2 bytes per slot, little-endian.
    // Slots 0-7: P-256 private key slots.
    //  WriteConfig=0x2 (Always), IsSecret=1, ReadKey=0x0, NoMac=0, LimitedUse=0.
    //  Byte 0 low nibble = ReadKey (0), high nibble = NoMac/LimitedUse/EncRead/IsSecret.
    //  We encode an "always writable, secret" private-key slot as 0x8720.
    for slot in 0..8 {
        let off = 20 + slot * 2;
        config[off] = 0x87;
        config[off + 1] = 0x20;
    }
    // Slots 8-15: general data slots. WriteConfig=Always, IsSecret=0.
    for slot in 8..16 {
        let off = 20 + slot * 2;
        config[off] = 0x0F;
        config[off + 1] = 0x0F;
    }

    // Counter values at config[52..84] left as zeros (no counter usage in v1).

    // UseLock, VolatileKeyPermission, SecureBoot, KdfIvLoc etc. at config[68..75]
    // left as zeros — defaults fine for our scope.

    // ChipMode at config[85]: leave zero (I2C mode, TTL disabled).

    // Lock bytes: ship the device LOCKED out of the box. wolfSSL's
    // atcab_is_locked() refuses operations on unlocked zones.
    config[86] = 0x00; // LockValue: Data+OTP locked
    config[87] = 0x00; // LockConfig: Config locked

    // SlotLocked at config[88..90]: all 16 slots UNLOCKED (bit=1) so wolfSSL
    // can still GenKey / Write individual slots even with global zones locked.
    config[88] = 0xFF;
    config[89] = 0xFF;

    // ChipOptions at config[90..92]: leave zero.
    // X509format at config[92..96]: leave zero.

    // KeyConfig at config[96..128], 2 bytes per slot, little-endian.
    // Slots 0-7: Private=1, PubInfo=1, KeyType=4 (P-256), Lockable=1, ReqRandom=0,
    //  ReqAuth=0, AuthKey=0. Encoded as 0x33 0x00.
    for slot in 0..8 {
        let off = 96 + slot * 2;
        config[off] = 0x33;
        config[off + 1] = 0x00;
    }
    // Slots 8-15: KeyType=7 (not an ECC key / generic data), Lockable=1.
    for slot in 8..16 {
        let off = 96 + slot * 2;
        config[off] = 0x3C;
        config[off + 1] = 0x00;
    }

    let slots = (0..NUM_SLOTS).map(|_| SlotData::empty()).collect();
    Device {
        config,
        otp: [0; OTP_SIZE],
        slots,
    }
}

/// Shared device state + its backing file path. Wrapped in a Mutex by callers
/// (the TCP server keeps an `Arc<Mutex<Store>>`).
pub struct Store {
    pub device: Device,
    pub path: Option<PathBuf>,
}

impl Store {
    pub fn fresh() -> Self {
        Self { device: default_device(), path: None }
    }

    /// Load from disk if the file exists, otherwise initialize with defaults
    /// and write it out.
    pub fn load_or_init(path: &Path) -> std::io::Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            let device: Device = serde_json::from_slice(&bytes).map_err(io_err)?;
            Ok(Self { device, path: Some(path.to_path_buf()) })
        } else {
            let s = Self { device: default_device(), path: Some(path.to_path_buf()) };
            s.persist()?;
            Ok(s)
        }
    }

    pub fn persist(&self) -> std::io::Result<()> {
        if let Some(p) = &self.path {
            let bytes = serde_json::to_vec_pretty(&self.device).map_err(io_err)?;
            std::fs::write(p, bytes)?;
        }
        Ok(())
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// Global shared store used by the TCP server. Integration tests that want an
/// isolated store should construct their own `Store::fresh()`.
pub type SharedStore = std::sync::Arc<Mutex<Store>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_device_is_locked() {
        let d = default_device();
        assert!(d.config_locked());
        assert!(d.data_locked());
    }

    #[test]
    fn default_device_slots_unlocked() {
        let d = default_device();
        for slot in 0..NUM_SLOTS {
            assert!(!d.slot_locked(slot), "slot {} expected unlocked", slot);
        }
    }

    #[test]
    fn slot_lock_toggle_round_trip() {
        let mut d = default_device();
        d.set_slot_locked(3, true);
        assert!(d.slot_locked(3));
        d.set_slot_locked(3, false);
        assert!(!d.slot_locked(3));
    }

    #[test]
    fn serde_round_trip() {
        let d = default_device();
        let json = serde_json::to_string(&d).unwrap();
        let back: Device = serde_json::from_str(&json).unwrap();
        assert_eq!(back.config, d.config);
        assert_eq!(back.otp, d.otp);
        assert_eq!(back.slots.len(), d.slots.len());
    }
}
