/* types.rs
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

use serde::{Deserialize, Serialize};

pub const CONFIG_SIZE: usize = 128;
pub const OTP_SIZE: usize = 64;
pub const NUM_SLOTS: usize = 16;
pub const SLOT_SIZE: usize = 72;

/// Zone identifier bytes used by the Read/Write/Lock commands.
/// (Matches `ATCA_ZONE_CONFIG` et al. in cryptoauthlib.)
pub mod zone {
    pub const CONFIG: u8 = 0x00;
    pub const OTP: u8 = 0x01;
    pub const DATA: u8 = 0x02;
}

/// Full device state persisted to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    #[serde(with = "serde_byte_array_128")]
    pub config: [u8; CONFIG_SIZE],
    #[serde(with = "serde_byte_array_64")]
    pub otp: [u8; OTP_SIZE],
    pub slots: Vec<SlotData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotData {
    /// Raw slot data (up to 72 bytes). For ECC private key slots this holds
    /// the 32-byte big-endian scalar in the first 32 bytes.
    pub data: Vec<u8>,
}

impl SlotData {
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }
}

impl Device {
    /// Accessors that read the SDK-defined state from the config zone so we
    /// don't diverge between in-memory flags and the zone bytes wolfSSL reads.
    pub fn config_locked(&self) -> bool {
        self.config[87] != 0x55
    }
    pub fn data_locked(&self) -> bool {
        self.config[86] != 0x55
    }
    /// Bit `i` clear in the SlotLocked word (config[88..90]) means slot `i` is
    /// locked. Bit set means unlocked. This matches the datasheet.
    pub fn slot_locked(&self, slot: usize) -> bool {
        let word = u16::from_le_bytes([self.config[88], self.config[89]]);
        (word >> slot) & 1 == 0
    }

    pub fn set_config_locked(&mut self, locked: bool) {
        self.config[87] = if locked { 0x00 } else { 0x55 };
    }
    pub fn set_data_locked(&mut self, locked: bool) {
        self.config[86] = if locked { 0x00 } else { 0x55 };
    }
    pub fn set_slot_locked(&mut self, slot: usize, locked: bool) {
        let mut word = u16::from_le_bytes([self.config[88], self.config[89]]);
        if locked {
            word &= !(1u16 << slot);
        } else {
            word |= 1u16 << slot;
        }
        let b = word.to_le_bytes();
        self.config[88] = b[0];
        self.config[89] = b[1];
    }
}

// serde doesn't derive Serialize/Deserialize for fixed-size arrays larger
// than 32 by default. Hand-roll wrappers for the two sizes we need.
mod serde_byte_array_128 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(a: &[u8; 128], s: S) -> Result<S::Ok, S::Error> {
        a.as_ref().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 128], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.as_slice().try_into().map_err(|_| serde::de::Error::custom("expected 128 bytes"))
    }
}

mod serde_byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(a: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        a.as_ref().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.as_slice().try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
