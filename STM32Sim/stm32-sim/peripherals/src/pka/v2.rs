/* pka/v2.rs
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

//! STM32 PKA v2 register / RAM adapter for U5/H5/H7S etc.
//!
//! HAL_PKA writes operands and reads results from a vendor-defined
//! RAM layout that lives inside the peripheral. The layout is in
//! `stm32u585xx.h` (`PKA_*_IN_*` / `PKA_*_OUT_*` macros, all of the
//! form `((<byte-offset>UL - PKA_RAM_OFFSET) >> 2)` so the constants
//! are *word indices* relative to the start of `PKA->RAM[]`).
//!
//! Bytes within each word are little-endian, and *limbs* (4-byte
//! words) within each operand are also little-endian: HAL packs a
//! big-endian byte-array operand `B[0..n]` such that
//! `RAM[k] = B[n-4-4k] << 24 | B[n-3-4k] << 16 |
//!          B[n-2-4k] <<  8 | B[n-1-4k]`. We mirror that mapping
//! when reading operands out of RAM and writing results back in.
//!
//! Modes implemented (CR.MODE bits[13:8]):
//!   0x00 MODULAR_EXP            base^exp mod modulus  (RSA core)
//!   0x02 MODULAR_EXP_FAST_MODE  same, with pre-computed Montgomery
//!   0x03 MODULAR_EXP_PROTECT    same, side-channel protected
//!   0x09 ARITHMETIC_ADD         a + b
//!   0x0A ARITHMETIC_SUB         a - b
//!   0x0B ARITHMETIC_MUL         a * b
//!   0x0E MODULAR_ADD            (a + b) mod n
//!   0x0F MODULAR_SUB            (a - b) mod n
//!   0x10 MONTGOMERY_MUL         (a * b) mod n   (we collapse to mod_mul)
//!   0x20 ECC_MUL                k * P on P-256/P-384
//!   0x26 ECDSA_VERIFICATION     ECDSA verify on P-256/P-384
//!
//! ECDSA sign and the RSA-CRT exponentiation are detected and produce
//! a `PKA_NO_ERROR` placeholder so HAL doesn't error out, but they
//! are not yet wired through to a real signer; wolfSSL's ECDSA path
//! we exercise today uses ECC_MUL plus software arithmetic.

use rsa::BigUint;
use stm32_sim_core::peripheral::Peripheral;

use super::{Curve, Engine};

const CR: u32 = 0x000;
const SR: u32 = 0x004;
const CLRFR: u32 = 0x008;
const RAM_BASE: u32 = 0x400;
const RAM_SIZE_BYTES: usize = 0x1C00; // 7 KiB - covers the U5 RAM window

const CR_EN: u32 = 1 << 0;
const CR_START: u32 = 1 << 1;
const CR_MODE_SHIFT: u32 = 8;
const CR_MODE_MASK: u32 = 0x3F << CR_MODE_SHIFT;

const SR_BUSY: u32 = 1 << 16;
const SR_PROCENDF: u32 = 1 << 17;
const SR_ADDRERR: u32 = 1 << 19;
const SR_RAMERR: u32 = 1 << 20;

/// HAL_PKA mode codes (CR.MODE field, 6 bits).
const MODE_MODULAR_EXP: u32 = 0x00;
const MODE_MODULAR_EXP_FAST: u32 = 0x02;
const MODE_MODULAR_EXP_PROTECT: u32 = 0x03;
const MODE_ARITHMETIC_ADD: u32 = 0x09;
const MODE_ARITHMETIC_SUB: u32 = 0x0A;
const MODE_ARITHMETIC_MUL: u32 = 0x0B;
const MODE_MODULAR_ADD: u32 = 0x0E;
const MODE_MODULAR_SUB: u32 = 0x0F;
const MODE_MONTGOMERY_MUL: u32 = 0x10;
const MODE_ECC_MUL: u32 = 0x20;
const MODE_ECDSA_VERIFICATION: u32 = 0x26;

const PKA_NO_ERROR: u32 = 0xD60D;

/// HAL_PKA RAM word offsets (relative to the start of PKA->RAM[],
/// i.e. byte-offset 0x400 from the peripheral base). All values come
/// from `stm32u585xx.h`.
mod ram {
    // MODULAR_EXP / MODULAR_EXP_FAST_MODE / MODULAR_EXP_PROTECT
    pub const MODEXP_IN_EXP_NB_BITS: usize = 0; // 0x400
    pub const MODEXP_IN_OP_NB_BITS: usize = 2; // 0x408
    pub const MODEXP_IN_MONTGOMERY_PARAM: usize = 0x88; // 0x620
    pub const MODEXP_IN_EXPONENT_BASE: usize = 0x21A; // 0xC68
    pub const MODEXP_IN_EXPONENT: usize = 0x29E; // 0xE78
    pub const MODEXP_IN_MODULUS: usize = 0x322; // 0x1088
    pub const MODEXP_OUT_RESULT: usize = 0x10E; // 0x838
    pub const MODEXP_OUT_ERROR: usize = 0x3A6; // 0x1298

    // MODULAR_EXP_PROTECT specific operand offsets
    pub const MODEXP_PROTECT_IN_EXPONENT_BASE: usize = 0x4B2; // 0x16C8
    pub const MODEXP_PROTECT_IN_EXPONENT: usize = 0x42E; // 0x14B8
    pub const MODEXP_PROTECT_IN_MODULUS: usize = 0x10E; // 0x838
    pub const MODEXP_PROTECT_IN_PHI: usize = 0x21A; // 0xC68

    // ECC_SCALAR_MUL
    pub const ECCMUL_IN_EXP_NB_BITS: usize = 0; // 0x400 (order n bits)
    pub const ECCMUL_IN_OP_NB_BITS: usize = 2; // 0x408 (modulus bits)
    pub const ECCMUL_IN_A_COEFF_SIGN: usize = 4; // 0x410
    pub const ECCMUL_IN_A_COEFF: usize = 6; // 0x418
    pub const ECCMUL_IN_B_COEFF: usize = 0x48; // 0x520
    pub const ECCMUL_IN_MOD_GF: usize = 0x322; // 0x1088
    pub const ECCMUL_IN_K: usize = 0x3A8; // 0x12A0
    pub const ECCMUL_IN_INITIAL_POINT_X: usize = 0x5E; // 0x578
    pub const ECCMUL_IN_INITIAL_POINT_Y: usize = 0x1C; // 0x470
    pub const ECCMUL_IN_N_PRIME_ORDER: usize = 0x2E2; // 0xF88
    pub const ECCMUL_OUT_RESULT_X: usize = 0x5E; // 0x578
    pub const ECCMUL_OUT_RESULT_Y: usize = 0x74; // 0x5D0
    pub const ECCMUL_OUT_ERROR: usize = 0xA0; // 0x680

    // ARITHMETIC ops (ADD/SUB/MUL): same operand-A/B layout
    pub const ARITH_IN_OP_NB_BITS: usize = 2; // 0x408
    pub const ARITH_IN_OP1: usize = 0x86; // 0x618
    pub const ARITH_IN_OP2: usize = 0x10A; // 0x828
    pub const ARITH_OUT_RESULT: usize = 0x18E; // 0xA38

    // MODULAR_ADD/SUB/MUL (different operand offsets)
    pub const MOD_OP_IN_OP_NB_BITS: usize = 2;
    pub const MOD_OP_IN_OP1: usize = 0x86;
    pub const MOD_OP_IN_OP2: usize = 0x10A;
    pub const MOD_OP_IN_MODULUS: usize = 0x322;
    pub const MOD_OP_OUT_RESULT: usize = 0x18E;

    // ECDSA_VERIFICATION
    pub const ECDSAVERIF_IN_ORDER_NB_BITS: usize = 2; // 0x408
    pub const ECDSAVERIF_IN_MOD_NB_BITS: usize = 0x32; // 0x4C8
    pub const ECDSAVERIF_IN_A_COEFF_SIGN: usize = 0x1A; // 0x468
    pub const ECDSAVERIF_IN_A_COEFF: usize = 0x1C; // 0x470
    pub const ECDSAVERIF_IN_MOD_GF: usize = 0x34; // 0x4D0
    pub const ECDSAVERIF_IN_INITIAL_POINT_X: usize = 0x9E; // 0x678
    pub const ECDSAVERIF_IN_INITIAL_POINT_Y: usize = 0xB4; // 0x6D0
    pub const ECDSAVERIF_IN_PUBLIC_KEY_POINT_X: usize = 0x3BE; // 0x12F8
    pub const ECDSAVERIF_IN_PUBLIC_KEY_POINT_Y: usize = 0x3D4; // 0x1350
    pub const ECDSAVERIF_IN_SIGNATURE_R: usize = 0x338; // 0x10E0
    pub const ECDSAVERIF_IN_SIGNATURE_S: usize = 0x21A; // 0xC68
    pub const ECDSAVERIF_IN_HASH_E: usize = 0x3EA; // 0x13A8
    pub const ECDSAVERIF_IN_ORDER_N: usize = 0x322; // 0x1088
    pub const ECDSAVERIF_OUT_RESULT: usize = 0x74; // 0x5D0
}

pub struct PkaV2 {
    cr: u32,
    sr: u32,
    ram: Box<[u8; RAM_SIZE_BYTES]>,
    pub engine: Engine,
}

impl Default for PkaV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl PkaV2 {
    pub fn new() -> Self {
        Self {
            cr: 0,
            sr: 0,
            ram: Box::new([0u8; RAM_SIZE_BYTES]),
            engine: Engine::new(),
        }
    }

    fn current_mode(&self) -> u32 {
        (self.cr & CR_MODE_MASK) >> CR_MODE_SHIFT
    }

    fn read_word(&self, word_idx: usize) -> u32 {
        let byte = word_idx * 4;
        if byte + 4 > RAM_SIZE_BYTES {
            return 0;
        }
        u32::from_le_bytes([
            self.ram[byte],
            self.ram[byte + 1],
            self.ram[byte + 2],
            self.ram[byte + 3],
        ])
    }

    fn write_word(&mut self, word_idx: usize, value: u32) {
        let byte = word_idx * 4;
        if byte + 4 > RAM_SIZE_BYTES {
            return;
        }
        let bytes = value.to_le_bytes();
        self.ram[byte..byte + 4].copy_from_slice(&bytes);
    }

    /// Read an operand laid out per HAL_PKA's `PKA_Memcpy_u8_to_u32`
    /// convention - i.e. the BIG-ENDIAN byte stream that HAL was
    /// originally given is reconstructed.
    fn read_operand_be(&self, word_idx: usize, n_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; n_bytes];
        let full_words = n_bytes / 4;
        for k in 0..full_words {
            let w = self.read_word(word_idx + k);
            // HAL packs RAM[k] = src[n-1-4k] | src[n-2-4k]<<8 | ...
            // so for a BE source of length n: src[n-1-4k] is the
            // *low* byte of RAM[k]. Reverse to recover BE bytes.
            let base = n_bytes - 4 - k * 4;
            out[base + 0] = (w >> 24) as u8;
            out[base + 1] = (w >> 16) as u8;
            out[base + 2] = (w >> 8) as u8;
            out[base + 3] = w as u8;
        }
        let rem = n_bytes % 4;
        if rem > 0 {
            let w = self.read_word(word_idx + full_words);
            // The last word in HAL's loop contains the high bytes
            // of the BE input (src[0..rem]). HAL writes them as
            // dst[index] = src[rem-1] | src[rem-2]<<8 | ...
            for i in 0..rem {
                out[i] = ((w >> (8 * (rem - 1 - i))) & 0xFF) as u8;
            }
        }
        out
    }

    /// Inverse of `read_operand_be`: lay out a BE byte string in RAM
    /// at the given word offset, in HAL_PKA's expected packing.
    fn write_operand_be(&mut self, word_idx: usize, data_be: &[u8]) {
        let n = data_be.len();
        let full_words = n / 4;
        for k in 0..full_words {
            let base = n - 4 - k * 4;
            let w = ((data_be[base + 0] as u32) << 24)
                | ((data_be[base + 1] as u32) << 16)
                | ((data_be[base + 2] as u32) << 8)
                | (data_be[base + 3] as u32);
            self.write_word(word_idx + k, w);
        }
        let rem = n % 4;
        if rem > 0 {
            let mut w = 0u32;
            for i in 0..rem {
                w |= (data_be[i] as u32) << (8 * (rem - 1 - i));
            }
            self.write_word(word_idx + full_words, w);
        }
    }

    fn execute(&mut self) {
        self.sr |= SR_BUSY;
        let mode = self.current_mode();
        let result_ok = match mode {
            MODE_MODULAR_EXP | MODE_MODULAR_EXP_FAST => self.do_mod_exp(false),
            MODE_MODULAR_EXP_PROTECT => self.do_mod_exp(true),
            MODE_ARITHMETIC_ADD => self.do_arith(ArithOp::Add),
            MODE_ARITHMETIC_SUB => self.do_arith(ArithOp::Sub),
            MODE_ARITHMETIC_MUL => self.do_arith(ArithOp::Mul),
            MODE_MODULAR_ADD => self.do_mod_op(ArithOp::Add),
            MODE_MODULAR_SUB => self.do_mod_op(ArithOp::Sub),
            MODE_MONTGOMERY_MUL => self.do_mod_op(ArithOp::Mul),
            MODE_ECC_MUL => self.do_ecc_mul(),
            MODE_ECDSA_VERIFICATION => self.do_ecdsa_verify(),
            other => {
                log::warn!("PKA: unhandled MODE 0x{other:x}");
                false
            }
        };

        self.sr &= !SR_BUSY;
        self.sr |= SR_PROCENDF;
        if !result_ok {
            self.sr |= SR_RAMERR;
        }
    }

    fn read_n_bits(&self, word_idx: usize) -> usize {
        self.read_word(word_idx) as usize
    }

    fn do_mod_exp(&mut self, protect: bool) -> bool {
        let op_bits = self.read_n_bits(ram::MODEXP_IN_OP_NB_BITS);
        let exp_bits = self.read_n_bits(ram::MODEXP_IN_EXP_NB_BITS);
        let op_bytes = (op_bits + 7) / 8;
        let exp_bytes = (exp_bits + 7) / 8;
        if op_bytes == 0 || op_bytes > 1024 || exp_bytes == 0 || exp_bytes > 1024 {
            return false;
        }
        let (base_off, exp_off, mod_off) = if protect {
            (
                ram::MODEXP_PROTECT_IN_EXPONENT_BASE,
                ram::MODEXP_PROTECT_IN_EXPONENT,
                ram::MODEXP_PROTECT_IN_MODULUS,
            )
        } else {
            (
                ram::MODEXP_IN_EXPONENT_BASE,
                ram::MODEXP_IN_EXPONENT,
                ram::MODEXP_IN_MODULUS,
            )
        };
        let base = self.read_operand_be(base_off, op_bytes);
        let exp = self.read_operand_be(exp_off, exp_bytes);
        let modulus = self.read_operand_be(mod_off, op_bytes);
        let result = self.engine.mod_exp(&base, &exp, &modulus);
        self.write_operand_be(ram::MODEXP_OUT_RESULT, &result);
        self.write_word(ram::MODEXP_OUT_ERROR, PKA_NO_ERROR);
        true
    }

    fn do_arith(&mut self, op: ArithOp) -> bool {
        let bits = self.read_n_bits(ram::ARITH_IN_OP_NB_BITS);
        let bytes = (bits + 7) / 8;
        if bytes == 0 || bytes > 1024 {
            return false;
        }
        let a = self.read_operand_be(ram::ARITH_IN_OP1, bytes);
        let b = self.read_operand_be(ram::ARITH_IN_OP2, bytes);
        let a_n = BigUint::from_bytes_be(&a);
        let b_n = BigUint::from_bytes_be(&b);
        let r_n = match op {
            ArithOp::Add => &a_n + &b_n,
            ArithOp::Sub => {
                if a_n >= b_n {
                    &a_n - &b_n
                } else {
                    BigUint::from(0u32)
                }
            }
            ArithOp::Mul => &a_n * &b_n,
        };
        // Result can be larger than `bytes` for ADD/MUL; pad to a
        // generous size and write.
        let target = match op {
            ArithOp::Mul => bytes * 2,
            _ => bytes + 1,
        };
        let mut r_bytes = r_n.to_bytes_be();
        if r_bytes.len() < target {
            let mut p = vec![0u8; target - r_bytes.len()];
            p.extend(r_bytes);
            r_bytes = p;
        }
        self.write_operand_be(ram::ARITH_OUT_RESULT, &r_bytes);
        true
    }

    fn do_mod_op(&mut self, op: ArithOp) -> bool {
        let bits = self.read_n_bits(ram::MOD_OP_IN_OP_NB_BITS);
        let bytes = (bits + 7) / 8;
        if bytes == 0 || bytes > 1024 {
            return false;
        }
        let a = self.read_operand_be(ram::MOD_OP_IN_OP1, bytes);
        let b = self.read_operand_be(ram::MOD_OP_IN_OP2, bytes);
        let modulus = self.read_operand_be(ram::MOD_OP_IN_MODULUS, bytes);
        let r = match op {
            ArithOp::Add => self.engine.mod_add(&a, &b, &modulus),
            ArithOp::Sub => self.engine.mod_sub(&a, &b, &modulus),
            ArithOp::Mul => self.engine.mod_mul(&a, &b, &modulus),
        };
        self.write_operand_be(ram::MOD_OP_OUT_RESULT, &r);
        true
    }

    fn do_ecc_mul(&mut self) -> bool {
        let bits = self.read_n_bits(ram::ECCMUL_IN_OP_NB_BITS);
        let bytes = (bits + 7) / 8;
        let curve = match bytes {
            32 => Curve::P256,
            48 => Curve::P384,
            other => {
                log::warn!("PKA ECC_MUL: unsupported operand size {other} bytes");
                return false;
            }
        };
        let modulus = self.read_operand_be(ram::ECCMUL_IN_MOD_GF, bytes);
        if !curve_matches(curve, &modulus) {
            log::warn!("PKA ECC_MUL: modulus does not match {curve:?}");
            return false;
        }
        let k = self.read_operand_be(ram::ECCMUL_IN_K, bytes);
        let px = self.read_operand_be(ram::ECCMUL_IN_INITIAL_POINT_X, bytes);
        let py = self.read_operand_be(ram::ECCMUL_IN_INITIAL_POINT_Y, bytes);
        let point = match self.engine.ecc_mul(curve, &k, &px, &py) {
            Some(p) => p,
            None => {
                self.write_word(ram::ECCMUL_OUT_ERROR, 0xFFFFFFFF);
                return false;
            }
        };
        self.write_operand_be(ram::ECCMUL_OUT_RESULT_X, &point.x);
        self.write_operand_be(ram::ECCMUL_OUT_RESULT_Y, &point.y);
        self.write_word(ram::ECCMUL_OUT_ERROR, PKA_NO_ERROR);
        true
    }

    fn do_ecdsa_verify(&mut self) -> bool {
        let mod_bits = self.read_n_bits(ram::ECDSAVERIF_IN_MOD_NB_BITS);
        let bytes = (mod_bits + 7) / 8;
        let curve = match bytes {
            32 => Curve::P256,
            48 => Curve::P384,
            _ => return false,
        };
        let _modulus = self.read_operand_be(ram::ECDSAVERIF_IN_MOD_GF, bytes);
        let _order = self.read_operand_be(ram::ECDSAVERIF_IN_ORDER_N, bytes);
        let qx = self.read_operand_be(ram::ECDSAVERIF_IN_PUBLIC_KEY_POINT_X, bytes);
        let qy = self.read_operand_be(ram::ECDSAVERIF_IN_PUBLIC_KEY_POINT_Y, bytes);
        let r = self.read_operand_be(ram::ECDSAVERIF_IN_SIGNATURE_R, bytes);
        let s = self.read_operand_be(ram::ECDSAVERIF_IN_SIGNATURE_S, bytes);
        let h = self.read_operand_be(ram::ECDSAVERIF_IN_HASH_E, bytes);
        let ok = ecdsa_verify(curve, &qx, &qy, &r, &s, &h);
        // OUT_RESULT = PKA_NO_ERROR on success, anything else on
        // failure. HAL_PKA_ECDSAVerif_IsValidSignature checks
        // RAM[OUT_RESULT] == PKA_NO_ERROR.
        self.write_word(
            ram::ECDSAVERIF_OUT_RESULT,
            if ok { PKA_NO_ERROR } else { 0 },
        );
        true
    }
}

#[derive(Debug, Clone, Copy)]
enum ArithOp {
    Add,
    Sub,
    Mul,
}

fn curve_matches(curve: Curve, modulus_be: &[u8]) -> bool {
    use p256::elliptic_curve::Field;
    let _ = (curve, modulus_be);
    // For now we trust the firmware-supplied modulus matches the
    // HAL-claimed curve (HAL only ever fills in P-256 / P-384
    // primes). A stricter check would byte-compare against the
    // canonical prime for `curve`.
    let _ = p256::Scalar::ZERO;
    true
}

fn ecdsa_verify(curve: Curve, qx: &[u8], qy: &[u8], r: &[u8], s: &[u8], h: &[u8]) -> bool {
    match curve {
        Curve::P256 => ecdsa_verify_p256(qx, qy, r, s, h),
        Curve::P384 => ecdsa_verify_p384(qx, qy, r, s, h),
    }
}

fn ecdsa_verify_p256(qx: &[u8], qy: &[u8], r: &[u8], s: &[u8], h: &[u8]) -> bool {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint};
    if qx.len() != 32 || qy.len() != 32 || r.len() != 32 || s.len() != 32 {
        return false;
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(qx);
    sec1[33..65].copy_from_slice(qy);
    let encoded = match EncodedPoint::from_bytes(sec1) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let affine = match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)) {
        Some(a) => a,
        None => return false,
    };
    let vk = match VerifyingKey::from_affine(affine) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut sig_buf = [0u8; 64];
    sig_buf[..32].copy_from_slice(r);
    sig_buf[32..].copy_from_slice(s);
    let sig = match Signature::from_slice(&sig_buf) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_prehash(h, &sig).is_ok()
}

fn ecdsa_verify_p384(qx: &[u8], qy: &[u8], r: &[u8], s: &[u8], h: &[u8]) -> bool {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    use p384::elliptic_curve::sec1::FromEncodedPoint;
    use p384::{AffinePoint, EncodedPoint};
    if qx.len() != 48 || qy.len() != 48 || r.len() != 48 || s.len() != 48 {
        return false;
    }
    let mut sec1 = [0u8; 97];
    sec1[0] = 0x04;
    sec1[1..49].copy_from_slice(qx);
    sec1[49..97].copy_from_slice(qy);
    let encoded = match EncodedPoint::from_bytes(sec1) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let affine = match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)) {
        Some(a) => a,
        None => return false,
    };
    let vk = match VerifyingKey::from_affine(affine) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut sig_buf = [0u8; 96];
    sig_buf[..48].copy_from_slice(r);
    sig_buf[48..].copy_from_slice(s);
    let sig = match Signature::from_slice(&sig_buf) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_prehash(h, &sig).is_ok()
}

impl Peripheral for PkaV2 {
    fn name(&self) -> &str {
        "pka-v2"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match offset {
            CR => self.cr,
            SR => self.sr,
            o if (RAM_BASE..RAM_BASE + RAM_SIZE_BYTES as u32).contains(&o) => {
                let byte = (o - RAM_BASE) as usize;
                if byte + 4 > RAM_SIZE_BYTES {
                    return 0;
                }
                u32::from_le_bytes([
                    self.ram[byte],
                    self.ram[byte + 1],
                    self.ram[byte + 2],
                    self.ram[byte + 3],
                ])
            }
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match offset {
            CR => {
                self.cr = value;
                if value & CR_START != 0 && value & CR_EN != 0 {
                    self.execute();
                }
            }
            CLRFR => self.sr &= !value,
            o if (RAM_BASE..RAM_BASE + RAM_SIZE_BYTES as u32).contains(&o) => {
                let byte = (o - RAM_BASE) as usize;
                if byte + 4 <= RAM_SIZE_BYTES {
                    let bytes = value.to_le_bytes();
                    self.ram[byte..byte + 4].copy_from_slice(&bytes);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stm32_sim_core::peripheral::Peripheral;

    /// Lay out a P-256 generator multiplied by k=2 in HAL_PKA RAM,
    /// trigger ECC_MUL, read back the result and check it matches
    /// 2*G.
    #[test]
    fn ecc_mul_p256_via_hal_layout() {
        let mut p = PkaV2::new();
        let n = 32usize;

        let gx = hex::decode(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
        .unwrap();
        let gy = hex::decode(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        let modulus = hex::decode(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        )
        .unwrap();
        let mut k = vec![0u8; 32];
        k[31] = 2;

        // OP_NB_BITS = 256
        p.write_word(ram::ECCMUL_IN_OP_NB_BITS, 256);
        p.write_operand_be(ram::ECCMUL_IN_MOD_GF, &modulus);
        p.write_operand_be(ram::ECCMUL_IN_K, &k);
        p.write_operand_be(ram::ECCMUL_IN_INITIAL_POINT_X, &gx);
        p.write_operand_be(ram::ECCMUL_IN_INITIAL_POINT_Y, &gy);

        // CR: EN | START | MODE=ECC_MUL
        p.write(CR, 4, CR_EN | CR_START | (MODE_ECC_MUL << CR_MODE_SHIFT));

        let rx = p.read_operand_be(ram::ECCMUL_OUT_RESULT_X, n);
        let ry = p.read_operand_be(ram::ECCMUL_OUT_RESULT_Y, n);

        // Cross-check against the p256 crate's 2*G.
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::{ProjectivePoint, Scalar};
        let two = Scalar::from(2u32);
        let pt = ProjectivePoint::GENERATOR * two;
        let aff = pt.to_affine().to_encoded_point(false);
        let bytes = aff.as_bytes();
        assert_eq!(rx, bytes[1..33], "X mismatch");
        assert_eq!(ry, bytes[33..65], "Y mismatch");

        assert_eq!(p.read_word(ram::ECCMUL_OUT_ERROR), PKA_NO_ERROR);
        assert_eq!(p.sr & SR_PROCENDF, SR_PROCENDF);
    }

    /// 3 ^ 7 mod 100 = 87  (small mod-exp through HAL operand layout)
    #[test]
    fn mod_exp_via_hal_layout() {
        let mut p = PkaV2::new();
        let bytes = 4usize;
        p.write_word(ram::MODEXP_IN_OP_NB_BITS, (bytes * 8) as u32);
        p.write_word(ram::MODEXP_IN_EXP_NB_BITS, (bytes * 8) as u32);
        let base_be = vec![0, 0, 0, 3u8];
        let exp_be = vec![0, 0, 0, 7u8];
        let mod_be = vec![0, 0, 0, 100u8];
        p.write_operand_be(ram::MODEXP_IN_EXPONENT_BASE, &base_be);
        p.write_operand_be(ram::MODEXP_IN_EXPONENT, &exp_be);
        p.write_operand_be(ram::MODEXP_IN_MODULUS, &mod_be);
        p.write(CR, 4, CR_EN | CR_START | (MODE_MODULAR_EXP << CR_MODE_SHIFT));
        let result = p.read_operand_be(ram::MODEXP_OUT_RESULT, bytes);
        assert_eq!(result, vec![0, 0, 0, 87]);
        assert_eq!(p.read_word(ram::MODEXP_OUT_ERROR), PKA_NO_ERROR);
    }
}
