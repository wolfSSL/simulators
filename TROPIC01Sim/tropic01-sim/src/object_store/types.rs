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

/// Curves the TROPIC01 ECC engine supports. P-256 and Ed25519 are the only
/// two listed in `lt_l3_api_structs.h::lt_l3_ecc_key_generate_cmd_t`
/// (CURVE values 1 and 2).
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

/// `ECC_Key_Read.origin` field. The chip distinguishes keys it generated
/// internally from those uploaded with `ECC_Key_Store`. wolfSSL's port
/// reads this back via `lt_ecc_key_read` but treats both equivalently.
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

/// One ECC key slot. Private bytes are stored unmodified; the public key
/// is derived on demand by the handler so we don't have to re-derive it
/// across crate version bumps.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EccSlot {
    pub curve: CurveKind,
    pub origin: KeyOrigin,
    /// Raw private scalar bytes. 32B for both P-256 and Ed25519.
    pub private_key: Vec<u8>,
}

/// One R-memory slot. The chip allows arbitrary host-defined bytes up to
/// 444B per slot (`TR01_L3_R_MEM_DATA_*`); wolfSSL only ever stores 32B
/// values (AES key, IV, Ed25519 priv, Ed25519 pub).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RMemSlot {
    pub data: Vec<u8>,
}

/// One pairing-key slot. Holds the host's static X25519 public key the
/// chip will accept for handshakes targeting this slot. `is_valid` mirrors
/// the chip's per-slot "invalidated" bit (set by Pairing_Key_Invalidate).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingSlot {
    pub public_key: [u8; 32],
    pub is_valid: bool,
}

/// Persistent on-disk device state. All fields together define the
/// chip's identity, pairing trust anchors, and persistent key/data store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    /// 12-byte chip ID (silicon revision + unique device ID), returned by
    /// GET_INFO(object_id=CHIP_ID).
    pub chip_id: [u8; 12],
    /// Chip's static X25519 keypair (STPRIV/STPUB). The Noise_KK1 handshake
    /// uses STPUB. STPRIV never leaves the chip in real silicon.
    pub st_priv: [u8; 32],
    pub st_pub: [u8; 32],
    /// 4-cert "cert store" blob returned by GET_INFO(X509_CERTIFICATE).
    /// libtropic reads this in 128-byte chunks and parses the leading
    /// 10-byte header (`[version=1][num_certs=4][len_cert0..len_cert3 as
    /// 4 BE u16]`) followed by `num_certs` concatenated DER blobs. Cert 0
    /// is the device cert and must contain the X25519 SPKI carrying
    /// STPUB at a libtropic-recognisable ASN.1 offset; certs 1..3 are
    /// padding so the chunked reader walks all four boundaries cleanly.
    pub cert_store: Vec<u8>,
    /// Pairing-key slots 0..=3 (`TR01_L3_PAIRING_KEY_SLOT_*`).
    pub pairing_slots: BTreeMap<u8, PairingSlot>,
    /// ECC key slots. Slot indices follow libtropic's per-application
    /// convention; wolfSSL's port uses slot 1 for Ed25519.
    pub ecc_slots: BTreeMap<u16, EccSlot>,
    /// R-memory slots (host-defined arbitrary data).
    pub r_mem_slots: BTreeMap<u16, RMemSlot>,
}
