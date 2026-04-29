/* types.rs
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

use serde::{Deserialize, Serialize};

/// Types of EC curves supported by the simulator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ECCurve {
    NistP224,
    NistP256,
    NistP384,
    Ed25519,
    Curve25519,
}

impl ECCurve {
    /// Parse from the SE050 curve constant byte.
    pub fn from_se050_byte(b: u8) -> Option<Self> {
        match b {
            0x02 => Some(ECCurve::NistP224),
            0x03 => Some(ECCurve::NistP256),
            0x04 => Some(ECCurve::NistP384),
            0x40 => Some(ECCurve::Ed25519),
            0x41 => Some(ECCurve::Curve25519),
            _ => None,
        }
    }
}

/// RSA key components accumulated across per-component `WriteRSAKey` APDUs.
/// The SDK's `sss_key_store_set_key` for RSA parses the host DER and dispatches
/// N, E, D (non-CRT) or P, Q, DP, DQ, QINV (CRT) as successive APDUs addressing
/// the same object ID — none of which individually contain enough data to
/// reconstruct a usable key. The simulator stages the pieces here until the
/// set is complete, then materializes the PKCS#1 DER.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RsaComponents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qinv: Option<Vec<u8>>,
}

/// Secure objects stored in the simulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureObject {
    ECKeyPair {
        curve: ECCurve,
        /// Private key bytes (32 bytes for P-256/Ed25519)
        private_key: Vec<u8>,
        /// Public key bytes (65 bytes uncompressed for P-256, 32 bytes for Ed25519)
        public_key: Vec<u8>,
    },
    ECPublicKey {
        curve: ECCurve,
        public_key: Vec<u8>,
    },
    RSAKeyPair {
        key_size_bits: u16,
        /// PKCS#1 DER-encoded private key. Empty until enough components have
        /// been accumulated via per-component `WriteRSAKey` APDUs (or set all
        /// at once during keygen).
        private_key_der: Vec<u8>,
        /// Components staged across successive `WriteRSAKey` APDUs. Cleared
        /// once `private_key_der` is materialized.
        #[serde(default)]
        staged: RsaComponents,
    },
    AESKey {
        key: Vec<u8>,
    },
    Binary {
        data: Vec<u8>,
    },
    UserID {
        value: Vec<u8>,
    },
    Counter {
        value: u64,
    },
    HMACKey {
        key: Vec<u8>,
    },
}

impl SecureObject {
    /// Get the SE050 secure object type code (v7.2.0+ curve-specific for EC).
    pub fn type_code(&self) -> u8 {
        match self {
            SecureObject::ECKeyPair { curve, .. } => match curve {
                ECCurve::NistP224 => 0x25, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P224
                ECCurve::NistP256 => 0x29, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P256
                ECCurve::NistP384 => 0x2D, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P384
                ECCurve::Ed25519 => 0x65, // kSE05x_SecObjTyp_EC_KEY_PAIR_ED25519
                ECCurve::Curve25519 => 0x69, // kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519
            },
            SecureObject::ECPublicKey { curve, .. } => match curve {
                ECCurve::NistP224 => 0x26, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P224
                ECCurve::NistP256 => 0x2A, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P256
                ECCurve::NistP384 => 0x2E, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P384
                ECCurve::Ed25519 => 0x67, // kSE05x_SecObjTyp_EC_PUB_KEY_ED25519
                ECCurve::Curve25519 => 0x6B, // kSE05x_SecObjTyp_EC_PUB_KEY_MONT_DH_25519
            },
            SecureObject::RSAKeyPair { .. } => 0x04,
            SecureObject::AESKey { .. } => 0x09,
            SecureObject::Binary { .. } => 0x0B,
            SecureObject::UserID { .. } => 0x0C,
            SecureObject::Counter { .. } => 0x0D,
            SecureObject::HMACKey { .. } => 0x11,
        }
    }

    /// Get the SE050 EC curve ID for EC key objects.
    pub fn curve_id(&self) -> Option<u8> {
        let curve = match self {
            SecureObject::ECKeyPair { curve, .. } => Some(curve),
            SecureObject::ECPublicKey { curve, .. } => Some(curve),
            _ => None,
        }?;
        Some(match curve {
            ECCurve::NistP224 => 0x02,
            ECCurve::NistP256 => 0x03,
            ECCurve::NistP384 => 0x04,
            ECCurve::Ed25519 => 0x40,
            ECCurve::Curve25519 => 0x41,
        })
    }

    /// Get the size of the object's primary data in bytes.
    pub fn data_size(&self) -> usize {
        match self {
            SecureObject::ECKeyPair { public_key, .. } => public_key.len(),
            SecureObject::ECPublicKey { public_key, .. } => public_key.len(),
            SecureObject::RSAKeyPair { key_size_bits, .. } => (*key_size_bits as usize) / 8,
            SecureObject::AESKey { key } => key.len(),
            SecureObject::Binary { data } => data.len(),
            SecureObject::UserID { value } => value.len(),
            SecureObject::Counter { .. } => 8,
            SecureObject::HMACKey { key } => key.len(),
        }
    }
}
