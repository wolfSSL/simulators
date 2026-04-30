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

pub mod ecdh;
pub mod echo;
pub mod keypair;
pub mod query;
pub mod random;
pub mod read;
pub mod sign;
pub mod verify;

/// NIST P-256 OID encoded as STSELib expects:
///   length(2 BE) = 0x0008, value = 1.2.840.10045.3.1.7 OID bytes.
/// See `STSE_NIST_P_256_ID_VALUE` in core/stse_generic_typedef.h.
pub const NIST_P256_CURVE_ID: [u8; 10] = [
    0x00, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
];

/// Compare a curve_id payload (length-prefixed OID) against the supported
/// NIST P-256 encoding. Returns true if it matches, false otherwise.
pub fn is_nist_p256(curve_id: &[u8]) -> bool {
    curve_id == NIST_P256_CURVE_ID
}

/// `STSE_NIST_BRAINPOOL_POINT_REPRESENTATION_ID` from
/// core/stse_generic_typedef.h. Used as a single-byte tag preceding the
/// (length, X, length, Y) public key encoding.
pub const POINT_REPRESENTATION_UNCOMPRESSED: u8 = 0x04;
