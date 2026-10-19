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

/// Immutable metadata attached when a secure object is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Raw TAG_POLICY value, including one or more length-prefixed access
    /// rule entries. None means the applet's unrestricted default policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Vec<u8>>,
    /// SE05x_Origin_t: external/imported=1, internal/generated=2,
    /// trust-provisioned=3.
    #[serde(default = "default_object_origin")]
    pub origin: u8,
}

impl Default for ObjectMetadata {
    fn default() -> Self {
        Self {
            policy: None,
            origin: default_object_origin(),
        }
    }
}

fn default_object_origin() -> u8 {
    0x01
}

/// Types of EC curves supported by the simulator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ECCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    Ed25519,
    Curve25519,
}

impl ECCurve {
    /// Parse from the SE050 curve constant byte.
    pub fn from_se050_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(ECCurve::NistP192),
            0x02 => Some(ECCurve::NistP224),
            0x03 => Some(ECCurve::NistP256),
            0x04 => Some(ECCurve::NistP384),
            0x05 => Some(ECCurve::NistP521),
            0x40 => Some(ECCurve::Ed25519),
            0x41 => Some(ECCurve::Curve25519),
            _ => None,
        }
    }

    /// Scalar (private key / shared secret) size in bytes. This is
    /// also what ReadSize reports for EC key objects on real applets
    /// (bench-verified: 32 for P-256, 66 for P-521, 24 for P-192).
    pub fn scalar_len(self) -> usize {
        match self {
            ECCurve::NistP192 => 24,
            ECCurve::NistP224 => 28,
            ECCurve::NistP256 => 32,
            ECCurve::NistP384 => 48,
            ECCurve::NistP521 => 66,
            ECCurve::Ed25519 | ECCurve::Curve25519 => 32,
        }
    }

    /// Whether this is a Weierstrass curve that must exist as a
    /// parameterized curve object on the applet before key operations
    /// (25519 curves are built-in constants and need no curve object).
    pub fn needs_curve_object(self) -> bool {
        !matches!(self, ECCurve::Ed25519 | ECCurve::Curve25519)
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
        /// Counter size in bytes, fixed at creation (1..=8). Real
        /// applets return exactly this many bytes from ReadObject and
        /// this value from ReadSize (bench-verified with a 4-byte
        /// counter on applet 3.1.1 and 7.2.0).
        #[serde(default = "default_counter_size")]
        size: u16,
    },
    HMACKey {
        key: Vec<u8>,
        /// Union of the AR headers from the TAG_POLICY TLV attached at
        /// creation; None when the object was created with no policy.
        /// Kept as part of the object's attributes; note ReadObject
        /// refuses HMACKey objects regardless of this value, as real
        /// applets do (see crate::policy and object_mgmt::handle_read).
        #[serde(default)]
        policy: Option<u32>,
    },
}

impl SecureObject {
    /// Get the SE050 secure object type code as reported by ReadType.
    ///
    /// Applet 7.2 reports curve-specific EC type codes; applet 3.x
    /// reports the generic kSE05x_SecObjTyp_EC_KEY_PAIR (0x01) /
    /// EC_PUB_KEY (0x03). Bench-verified: a P-256 pair reads back 0x29
    /// on the SE051 and 0x01 on the SE050C; a P-521 pair reads 0x31 on
    /// the SE051 and 0x01 on the SE050C. The public-key and 25519
    /// generic codes follow the SDK's SE05x_SecureObjectType_t enum.
    pub fn type_code(&self, v7: bool) -> u8 {
        match self {
            SecureObject::ECKeyPair { curve, .. } => {
                if !v7 {
                    return 0x01; // kSE05x_SecObjTyp_EC_KEY_PAIR
                }
                match curve {
                    ECCurve::NistP192 => 0x21, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P192
                    ECCurve::NistP224 => 0x25, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P224
                    ECCurve::NistP256 => 0x29, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P256
                    ECCurve::NistP384 => 0x2D, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P384
                    ECCurve::NistP521 => 0x31, // kSE05x_SecObjTyp_EC_KEY_PAIR_NIST_P521
                    ECCurve::Ed25519 => 0x65, // kSE05x_SecObjTyp_EC_KEY_PAIR_ED25519
                    ECCurve::Curve25519 => 0x69, // kSE05x_SecObjTyp_EC_KEY_PAIR_MONT_DH_25519
                }
            }
            SecureObject::ECPublicKey { curve, .. } => {
                if !v7 {
                    return 0x03; // kSE05x_SecObjTyp_EC_PUB_KEY
                }
                match curve {
                    ECCurve::NistP192 => 0x22, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P192
                    ECCurve::NistP224 => 0x26, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P224
                    ECCurve::NistP256 => 0x2A, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P256
                    ECCurve::NistP384 => 0x2E, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P384
                    ECCurve::NistP521 => 0x32, // kSE05x_SecObjTyp_EC_PUB_KEY_NIST_P521
                    ECCurve::Ed25519 => 0x67, // kSE05x_SecObjTyp_EC_PUB_KEY_ED25519
                    ECCurve::Curve25519 => 0x6B, // kSE05x_SecObjTyp_EC_PUB_KEY_MONT_DH_25519
                }
            }
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
            ECCurve::NistP192 => 0x01,
            ECCurve::NistP224 => 0x02,
            ECCurve::NistP256 => 0x03,
            ECCurve::NistP384 => 0x04,
            ECCurve::NistP521 => 0x05,
            ECCurve::Ed25519 => 0x40,
            ECCurve::Curve25519 => 0x41,
        })
    }

    /// Size reported by ReadSize, in bytes. For EC objects real
    /// applets report the scalar size, not the encoded public key
    /// length (bench-verified: 32 for a P-256 pair, 66 for P-521,
    /// 24 for P-192); counters report their creation-time size.
    pub fn data_size(&self) -> usize {
        match self {
            SecureObject::ECKeyPair { curve, .. } => curve.scalar_len(),
            SecureObject::ECPublicKey { curve, .. } => curve.scalar_len(),
            SecureObject::RSAKeyPair { key_size_bits, .. } => (*key_size_bits as usize) / 8,
            SecureObject::AESKey { key } => key.len(),
            SecureObject::Binary { data } => data.len(),
            SecureObject::UserID { value } => value.len(),
            SecureObject::Counter { size, .. } => *size as usize,
            SecureObject::HMACKey { key, .. } => key.len(),
        }
    }
}

fn default_counter_size() -> u16 {
    8
}
