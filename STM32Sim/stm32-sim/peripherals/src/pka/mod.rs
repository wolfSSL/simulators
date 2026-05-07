/* pka/mod.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STM32Sim.
 *
 * STM32Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STM32Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

//! Public-Key Accelerator engine for STM32 PKA v1/v2.
//!
//! The PKA peripheral on STM32 chips that have it (L5/WB/WL = v1,
//! U5/H5/H7S/MP13/N6/WBA = v2) is a coprocessor with its own RAM
//! that performs:
//!   - Modular exponentiation (RSA core)
//!   - ECC scalar multiplication
//!   - ECDSA signing and verification
//!   - Modular add/sub/multiply
//!
//! This module implements the **mathematical engine** using
//! RustCrypto's `p256`, `p384`, and `rsa` crates. The per-revision
//! register-layer (`v2.rs`) marshals MMIO writes into `Engine` calls.
//!
//! `pka/v2.rs` models the vendor-internal RAM-offset layout that
//! HAL_PKA's operations expect (offsets per `stm32u585xx.h`, byte
//! packing per `PKA_Memcpy_u8_to_u32`), so an unmodified
//! `HAL_PKA_ModExp` / `HAL_PKA_ECCMul` / `HAL_PKA_ECDSAVerif` call
//! from wolfSSL's `WOLFSSL_STM32_PKA` path drives this engine
//! correctly end-to-end.

pub mod v2;

use rsa::BigUint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    pub fn byte_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Idle,
    EccMul(Curve),
    ModExp,
    ModAdd,
    ModSub,
    ModMul,
}

#[derive(Default)]
pub struct Engine {
    pub last_status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Idle,
    Ok,
    Error,
}

/// (X, Y) bytes, big-endian, padded to curve byte length.
#[derive(Debug, Clone)]
pub struct Point {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            last_status: Status::Idle,
        }
    }

    /// k * P on the chosen curve. Inputs are big-endian, padded to
    /// curve byte length. Returns (X, Y) of the result point.
    pub fn ecc_mul(&mut self, curve: Curve, k_be: &[u8], px_be: &[u8], py_be: &[u8]) -> Option<Point> {
        let result = match curve {
            Curve::P256 => Self::ecc_mul_p256(k_be, px_be, py_be),
            Curve::P384 => Self::ecc_mul_p384(k_be, px_be, py_be),
        };
        self.last_status = if result.is_some() { Status::Ok } else { Status::Error };
        result
    }

    fn ecc_mul_p256(k_be: &[u8], px_be: &[u8], py_be: &[u8]) -> Option<Point> {
        use p256::elliptic_curve::generic_array::GenericArray;
        use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
        use p256::elliptic_curve::PrimeField;
        use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

        if k_be.len() != 32 || px_be.len() != 32 || py_be.len() != 32 {
            return None;
        }
        let scalar = Option::<Scalar>::from(Scalar::from_repr(GenericArray::clone_from_slice(k_be)))?;

        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(px_be);
        sec1[33..65].copy_from_slice(py_be);
        let encoded = EncodedPoint::from_bytes(sec1).ok()?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;

        let proj = ProjectivePoint::from(affine) * scalar;
        let result_affine = AffinePoint::from(proj);
        let result_point = result_affine.to_encoded_point(false);
        let bytes = result_point.as_bytes();
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return None;
        }
        Some(Point {
            x: bytes[1..33].to_vec(),
            y: bytes[33..65].to_vec(),
        })
    }

    fn ecc_mul_p384(k_be: &[u8], px_be: &[u8], py_be: &[u8]) -> Option<Point> {
        use p384::elliptic_curve::generic_array::GenericArray;
        use p384::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
        use p384::elliptic_curve::PrimeField;
        use p384::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

        if k_be.len() != 48 || px_be.len() != 48 || py_be.len() != 48 {
            return None;
        }
        let scalar = Option::<Scalar>::from(Scalar::from_repr(GenericArray::clone_from_slice(k_be)))?;

        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..49].copy_from_slice(px_be);
        sec1[49..97].copy_from_slice(py_be);
        let encoded = EncodedPoint::from_bytes(sec1).ok()?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;
        let proj = ProjectivePoint::from(affine) * scalar;
        let result_affine = AffinePoint::from(proj);
        let result_point = result_affine.to_encoded_point(false);
        let bytes = result_point.as_bytes();
        if bytes.len() != 97 || bytes[0] != 0x04 {
            return None;
        }
        Some(Point {
            x: bytes[1..49].to_vec(),
            y: bytes[49..97].to_vec(),
        })
    }

    /// Compute base^exp mod modulus. All inputs big-endian.
    pub fn mod_exp(&mut self, base_be: &[u8], exp_be: &[u8], mod_be: &[u8]) -> Vec<u8> {
        let base = BigUint::from_bytes_be(base_be);
        let exp = BigUint::from_bytes_be(exp_be);
        let modulus = BigUint::from_bytes_be(mod_be);
        let result = if modulus == BigUint::from(0u32) {
            BigUint::from(0u32)
        } else {
            base.modpow(&exp, &modulus)
        };
        self.last_status = Status::Ok;
        pad_be(&result, mod_be.len())
    }

    /// (a + b) mod n
    pub fn mod_add(&mut self, a_be: &[u8], b_be: &[u8], n_be: &[u8]) -> Vec<u8> {
        let a = BigUint::from_bytes_be(a_be);
        let b = BigUint::from_bytes_be(b_be);
        let n = BigUint::from_bytes_be(n_be);
        if n == BigUint::from(0u32) {
            self.last_status = Status::Error;
            return vec![0u8; n_be.len()];
        }
        let r = (a + b) % &n;
        self.last_status = Status::Ok;
        pad_be(&r, n_be.len())
    }

    /// (a - b) mod n  (handles a < b by wrapping into [0, n))
    pub fn mod_sub(&mut self, a_be: &[u8], b_be: &[u8], n_be: &[u8]) -> Vec<u8> {
        let a = BigUint::from_bytes_be(a_be);
        let b = BigUint::from_bytes_be(b_be);
        let n = BigUint::from_bytes_be(n_be);
        if n == BigUint::from(0u32) {
            self.last_status = Status::Error;
            return vec![0u8; n_be.len()];
        }
        let r = if a >= b {
            (a - b) % &n
        } else {
            let diff = b - a;
            let m = &diff % &n;
            if m == BigUint::from(0u32) {
                m
            } else {
                &n - m
            }
        };
        self.last_status = Status::Ok;
        pad_be(&r, n_be.len())
    }

    /// (a * b) mod n
    pub fn mod_mul(&mut self, a_be: &[u8], b_be: &[u8], n_be: &[u8]) -> Vec<u8> {
        let a = BigUint::from_bytes_be(a_be);
        let b = BigUint::from_bytes_be(b_be);
        let n = BigUint::from_bytes_be(n_be);
        if n == BigUint::from(0u32) {
            self.last_status = Status::Error;
            return vec![0u8; n_be.len()];
        }
        let r = (a * b) % &n;
        self.last_status = Status::Ok;
        pad_be(&r, n_be.len())
    }
}

fn pad_be(v: &BigUint, n: usize) -> Vec<u8> {
    let mut out = v.to_bytes_be();
    if out.len() < n {
        let mut padded = vec![0u8; n - out.len()];
        padded.extend(out);
        out = padded;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// k=1 is a trivial KAT: 1*G should give back the curve's
    /// generator point.
    #[test]
    fn ecc_mul_p256_identity_with_one() {
        let gx = hex::decode(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
        .unwrap();
        let gy = hex::decode(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        let mut k = vec![0u8; 32];
        k[31] = 1;

        let mut e = Engine::new();
        let r = e.ecc_mul(Curve::P256, &k, &gx, &gy).expect("ecc_mul");
        assert_eq!(r.x, gx);
        assert_eq!(r.y, gy);
        assert_eq!(e.last_status, Status::Ok);
    }

    /// k=2 doubles the generator, cross-checked against the p256 crate.
    #[test]
    fn ecc_mul_p256_double_matches_p256_crate() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::ProjectivePoint;
        use p256::Scalar;

        let two = Scalar::from(2u32);
        let result = ProjectivePoint::GENERATOR * two;
        let aff = result.to_affine().to_encoded_point(false);
        let bytes = aff.as_bytes();

        let gx = hex::decode(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
        .unwrap();
        let gy = hex::decode(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        let mut k = vec![0u8; 32];
        k[31] = 2;

        let mut e = Engine::new();
        let r = e.ecc_mul(Curve::P256, &k, &gx, &gy).expect("ecc_mul");
        assert_eq!(&r.x, &bytes[1..33]);
        assert_eq!(&r.y, &bytes[33..65]);
    }

    /// 3^7 mod 100 = 2187 mod 100 = 87
    #[test]
    fn mod_exp_smoke() {
        let mut e = Engine::new();
        let out = e.mod_exp(&[3], &[7], &[100]);
        assert_eq!(out.last(), Some(&87));
    }

    #[test]
    fn mod_add_smoke() {
        let mut e = Engine::new();
        let out = e.mod_add(&[200], &[100], &[37]);
        // (200 + 100) % 37 = 4
        assert_eq!(out.last(), Some(&4));
    }
}
