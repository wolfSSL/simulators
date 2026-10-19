/* types.rs
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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::personality::Personality;

/// Bump when the persisted JSON layout changes incompatibly.
pub const STORE_FORMAT_VERSION: u32 = 2;

/// Number of 32-bit registers in the R-Config and I-Config objects
/// (addresses 0x000..0x1FC).
pub const CONFIG_REGISTERS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurveKind {
    P256,
    Ed25519,
}

impl CurveKind {
    pub fn wire_id(self) -> u8 {
        match self {
            CurveKind::P256 => 1,
            CurveKind::Ed25519 => 2,
        }
    }

    pub fn from_wire_id(v: u8) -> Option<Self> {
        match v {
            1 => Some(CurveKind::P256),
            2 => Some(CurveKind::Ed25519),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyOrigin {
    Generated,
    Stored,
}

impl KeyOrigin {
    pub fn wire_id(self) -> u8 {
        match self {
            KeyOrigin::Generated => 1,
            KeyOrigin::Stored => 2,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EccSlot {
    pub curve: CurveKind,
    pub origin: KeyOrigin,
    /// P-256: big-endian scalar. Ed25519: the 32-byte RFC 8032 secret.
    pub private_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairingState {
    Written,
    Invalidated,
}

/// A pairing key slot that is absent from `Device::pairing_slots` is blank.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingSlot {
    pub public_key: [u8; 32],
    pub state: PairingState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub format_version: u32,
    pub personality: Personality,
    /// 128-byte CHIP_ID object.
    pub chip_id: Vec<u8>,
    pub st_priv: [u8; 32],
    pub st_pub: [u8; 32],
    /// GET_INFO(X509_CERTIFICATE) blob: `[version][num_certs][4 x BE u16
    /// lengths][certs...]`.
    pub cert_store: Vec<u8>,
    pub pairing_slots: BTreeMap<u8, PairingSlot>,
    pub r_config: Vec<u32>,
    pub i_config: Vec<u32>,
    pub ecc_slots: BTreeMap<u16, EccSlot>,
    /// R-Memory user data slots; absent means empty.
    pub r_mem_slots: BTreeMap<u16, Vec<u8>>,
    /// Monotonic counters; absent means not initialized.
    pub mcounters: BTreeMap<u16, u32>,
    /// MAC-and-Destroy slots; absent means the erased value (all 0xFF).
    pub macandd_slots: BTreeMap<u16, [u8; 32]>,
    /// Device-unique MAC-and-Destroy keys used by F1 and F2.
    pub macandd_keys: [[u8; 32]; 2],
}

impl Device {
    /// Effective value of a configuration register: the R-Config value
    /// AND-ed with the I-Config value, as the firmware applies it.
    pub fn config(&self, addr: u16) -> u32 {
        let i = (addr as usize) / 4;
        self.r_config[i] & self.i_config[i]
    }
}
