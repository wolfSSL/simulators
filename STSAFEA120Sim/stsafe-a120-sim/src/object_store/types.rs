/* types.rs
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

use serde::{Deserialize, Serialize};

/// STSAFE-A120 supported curves -- only NIST P-256 is implemented in v1.
/// The discriminant matches `stse_ecc_key_type_t` when STSELib is built
/// with only `STSE_CONF_ECC_NIST_P_256` defined (see stse_generic_typedef.h).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurveKind {
    NistP256,
}

impl CurveKind {
    pub fn coordinate_size(self) -> usize {
        match self {
            CurveKind::NistP256 => 32,
        }
    }

    pub fn signature_size(self) -> usize {
        match self {
            CurveKind::NistP256 => 64,
        }
    }
}

/// A persistent ECC private key slot. Real silicon also tracks a
/// `usage_limit` counter that's decremented on every signing/ECDH
/// operation; the simulator does not model this -- wolfSSL's STSAFE
/// path always passes `usage_limit = 0` (unlimited), and adding
/// enforcement would create observable behavior the tests would have
/// to special-case without exercising any wolfSSL code path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EccSlot {
    pub curve: CurveKind,
    /// Raw 32-byte big-endian scalar.
    pub private_key: Vec<u8>,
}

/// A data-zone partition. STSAFE-A120 organises persistent storage as a list
/// of zones addressed by a 1-byte index. Zone 0 is conventionally the device
/// certificate zone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataZone {
    pub data: Vec<u8>,
}

/// On-disk persistent state. Slots and zones are sparse maps keyed by index
/// for forward compatibility -- new slot numbers don't break older stores.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    /// 8-byte unique identifier, returned by Query(PRODUCT_DATA).
    pub serial_number: [u8; 8],
    /// (slot_index -> ECC key) -- populated by Generate Key Pair.
    pub ecc_slots: std::collections::BTreeMap<u8, EccSlot>,
    /// (zone_index -> data) -- populated at provisioning, mutated by Update.
    pub data_zones: std::collections::BTreeMap<u8, DataZone>,
}
