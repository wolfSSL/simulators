/* cryp/v1.rs
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

//! STM32H7-style CRYP register file (HAL v1). See RM0433 §35.
//!
//! Register map (1 KiB peripheral, 4 KiB page on the bus):
//!   0x00 CR        Control
//!   0x04 SR        Status (read-only)
//!   0x08 DIN       Data input FIFO
//!   0x0C DOUT      Data output FIFO
//!   0x10 DMACR     DMA control (we accept writes, ignore them)
//!   0x14 IMSCR     Interrupt mask
//!   0x18 RISR      Raw interrupt status
//!   0x1C MISR      Masked interrupt status
//!   0x20..0x3C     K0LR..K3RR (8 words = 256-bit key)
//!   0x40..0x4C     IV0LR..IV1RR (4 words = 128-bit IV)

use stm32_sim_core::peripheral::Peripheral;

use super::gcm::{GcmPhase, GcmSession};
use super::{AesMode, CrypEngine, DataType, Direction, KeySize};

const CR: u32 = 0x00;
const SR: u32 = 0x04;
const DIN: u32 = 0x08;
const DOUT: u32 = 0x0C;
const DMACR: u32 = 0x10;
const IMSCR: u32 = 0x14;
const KEY_BASE: u32 = 0x20;
const KEY_END: u32 = 0x3C;
const IV_BASE: u32 = 0x40;
const IV_END: u32 = 0x4C;

// H7 CRYP_CR layout (RM0433 §35.7.1):
//   bit 14 FFLUSH (FIFO flush, write-1)
//   bit 15 CRYPEN (cryptographic processor enable)
//   bits[5:3] + bit 19  ALGOMODE[2:0] + ALGOMODE[3]
//   bits[17:16] GCM_CCMPH
//   bits[9:8] KEYSIZE  bits[7:6] DATATYPE  bit 2 ALGODIR
const CR_FFLUSH: u32 = 1 << 14;
const CR_CRYPEN: u32 = 1 << 15;
const CR_ALGODIR: u32 = 1 << 2;
const CR_ALGOMODE_LOW_SHIFT: u32 = 3;
const CR_ALGOMODE_LOW_MASK: u32 = 0x7 << CR_ALGOMODE_LOW_SHIFT;
const CR_ALGOMODE_HI: u32 = 1 << 19; // ALGOMODE[3]
const CR_DATATYPE_SHIFT: u32 = 6;
const CR_DATATYPE_MASK: u32 = 0x3 << CR_DATATYPE_SHIFT;
const CR_KEYSIZE_SHIFT: u32 = 8;
const CR_KEYSIZE_MASK: u32 = 0x3 << CR_KEYSIZE_SHIFT;
const CR_GCMPH_SHIFT: u32 = 16;
const CR_GCMPH_MASK: u32 = 0x3 << CR_GCMPH_SHIFT;

pub struct CrypV1 {
    cr: u32,
    key_regs: [u32; 8],
    iv_regs: [u32; 4],
    dmacr: u32,
    imscr: u32,
    pub engine: CrypEngine,
    gcm: GcmSession,
    /// 16-byte buffer accumulating DIN words while CRYP is in a GCM
    /// phase (the streaming engine is bypassed in that mode).
    gcm_in_buf: [u8; 16],
    gcm_in_len: usize,
}

impl Default for CrypV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl CrypV1 {
    pub fn new() -> Self {
        Self {
            cr: 0,
            key_regs: [0; 8],
            iv_regs: [0; 4],
            dmacr: 0,
            imscr: 0,
            engine: CrypEngine::default(),
            gcm: GcmSession::default(),
            gcm_in_buf: [0; 16],
            gcm_in_len: 0,
        }
    }

    fn gcm_phase(&self) -> GcmPhase {
        GcmPhase::from_bits((self.cr & CR_GCMPH_MASK) >> CR_GCMPH_SHIFT)
    }

    fn gcm_din(&mut self, value: u32) {
        if !self.engine.enabled || self.engine.mode != AesMode::Gcm {
            return;
        }
        let swapped = self.engine.datatype.swap(value);
        let bytes = swapped.to_be_bytes();
        for b in bytes {
            self.gcm_in_buf[self.gcm_in_len] = b;
            self.gcm_in_len += 1;
        }
        if self.gcm_in_len < 16 {
            return;
        }
        let block = self.gcm_in_buf;
        self.gcm_in_buf = [0; 16];
        self.gcm_in_len = 0;
        match self.gcm.phase {
            GcmPhase::Init => { /* INIT phase ignores DIN writes */ }
            GcmPhase::Header => {
                self.gcm.ingest_aad(&block);
            }
            GcmPhase::Payload => {
                let out = self
                    .gcm
                    .process_payload(self.engine.direction, &self.engine, &block);
                self.engine.stage_output(&out);
            }
            GcmPhase::Final => {
                let tag = self.gcm.finalise();
                self.engine.stage_output(&tag);
            }
        }
    }

    fn write_cr(&mut self, value: u32) {
        let was_enabled = self.cr & CR_CRYPEN != 0;
        let prev_cr = self.cr;
        self.cr = value & !CR_FFLUSH; // FFLUSH self-clears

        if value & CR_FFLUSH != 0 {
            self.engine.reset_fifos();
        }

        let now_enabled = self.cr & CR_CRYPEN != 0;
        if !was_enabled && now_enabled {
            self.commit_config();
            self.engine.enabled = true;
        } else if was_enabled && !now_enabled {
            self.engine.enabled = false;
        } else if now_enabled {
            // CRYPEN stayed on. HAL_CRYP_Decrypt does this: it switches
            // ALGOMODE to AES_KEY for round-key derivation, waits, then
            // switches back to ECB/CBC/CTR while CRYPEN is still 1.
            // We need to re-evaluate the engine config when relevant
            // CR bits change. GCM additionally has a phase machine
            // that must NOT be re-init'd on every CR write, so it
            // gets its own narrower re-eval path.
            let cfg_mask = CR_ALGOMODE_LOW_MASK
                | CR_ALGOMODE_HI
                | CR_ALGODIR
                | CR_KEYSIZE_MASK
                | CR_DATATYPE_MASK;
            if self.engine.mode == AesMode::Gcm {
                let phase = self.gcm_phase();
                if phase == GcmPhase::Init {
                    self.gcm.init(&self.engine);
                } else {
                    self.gcm.phase = phase;
                }
                self.gcm_in_buf = [0; 16];
                self.gcm_in_len = 0;
                self.engine.reset_fifos();
            } else if (prev_cr ^ self.cr) & cfg_mask != 0 {
                // Non-GCM mode change while enabled: rerun the
                // config commit so engine.mode/key/iv/etc. are
                // up to date.
                self.commit_config();
            }
        }
    }

    fn commit_config(&mut self) {
        let keysize_bits = (self.cr & CR_KEYSIZE_MASK) >> CR_KEYSIZE_SHIFT;
        self.engine.key_size = match keysize_bits {
            1 => KeySize::K192,
            2 => KeySize::K256,
            _ => KeySize::K128,
        };

        let datatype_bits = (self.cr & CR_DATATYPE_MASK) >> CR_DATATYPE_SHIFT;
        self.engine.datatype = DataType::from_bits(datatype_bits);

        self.engine.direction = if self.cr & CR_ALGODIR != 0 {
            Direction::Decrypt
        } else {
            Direction::Encrypt
        };

        let algomode_low = (self.cr & CR_ALGOMODE_LOW_MASK) >> CR_ALGOMODE_LOW_SHIFT;
        let algomode = algomode_low | if self.cr & CR_ALGOMODE_HI != 0 { 0x8 } else { 0 };

        self.engine.mode = match algomode {
            0b0100 => AesMode::Ecb,
            0b0101 => AesMode::Cbc,
            0b0110 => AesMode::Ctr,
            0b0111 => AesMode::KeyDerivation,
            0b1000 => AesMode::Gcm,
            other => {
                log::warn!(
                    "CRYP v1: unsupported ALGOMODE 0x{:x} (modelled: AES ECB/CBC/CTR/GCM)",
                    other
                );
                AesMode::Ecb
            }
        };

        self.engine.key = expand_key(&self.key_regs, self.engine.key_size);
        self.engine.iv = expand_iv(&self.iv_regs);
        self.engine.reset_fifos();
        self.gcm_in_buf = [0; 16];
        self.gcm_in_len = 0;

        if self.engine.mode == AesMode::Gcm {
            let phase = self.gcm_phase();
            if phase == GcmPhase::Init {
                self.gcm.init(&self.engine);
            } else {
                self.gcm.phase = phase;
            }
        }
    }

    fn compute_sr(&self) -> u32 {
        // STM32H7 CRYP_SR: bit 0 IFEM (input FIFO empty), bit 1 IFNF
        // (input FIFO not full), bit 2 OFNE (output not empty), bit 3
        // OFFU (output FIFO full), bit 4 BUSY. Our engine is
        // synchronous so BUSY stays 0; the HAL polls BUSY in tight
        // loops and immediate-zero is the right answer for an
        // instantaneous emulator.
        let mut sr = 0u32;
        if self.engine.input_empty() {
            sr |= 1 << 0;
        }
        if !self.engine.input_full() {
            sr |= 1 << 1;
        }
        if !self.engine.output_empty() {
            sr |= 1 << 2;
        }
        if self.engine.output_full() {
            sr |= 1 << 3;
        }
        sr
    }
}

fn key_word_be_bytes(w: u32) -> [u8; 4] {
    w.to_be_bytes()
}

fn expand_key(regs: &[u32; 8], size: KeySize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = match size {
        KeySize::K128 => 4, // K2LR..K3RR
        KeySize::K192 => 2, // K1LR..K3RR
        KeySize::K256 => 0, // K0LR..K3RR
    };
    let mut p = 0;
    for i in start..8 {
        let bytes = key_word_be_bytes(regs[i]);
        out[p..p + 4].copy_from_slice(&bytes);
        p += 4;
    }
    out
}

fn expand_iv(regs: &[u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, w) in regs.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

impl Peripheral for CrypV1 {
    fn name(&self) -> &str {
        "cryp-v1"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match offset {
            CR => self.cr,
            SR => self.compute_sr(),
            DIN => 0, // write-only on real hw; reads return 0
            DOUT => self.engine.read_dout(),
            DMACR => self.dmacr,
            IMSCR => self.imscr,
            0x18 | 0x1C => 0, // RISR / MISR (no interrupts modelled)
            o if (KEY_BASE..=KEY_END).contains(&o) => {
                let idx = ((o - KEY_BASE) / 4) as usize;
                self.key_regs[idx]
            }
            o if (IV_BASE..=IV_END).contains(&o) => {
                let idx = ((o - IV_BASE) / 4) as usize;
                self.iv_regs[idx]
            }
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match offset {
            CR => self.write_cr(value),
            DIN => {
                if self.engine.enabled && self.engine.mode == AesMode::Gcm {
                    self.gcm_din(value);
                } else {
                    self.engine.write_din(value);
                }
            }
            DMACR => self.dmacr = value,
            IMSCR => self.imscr = value,
            o if (KEY_BASE..=KEY_END).contains(&o) => {
                let idx = ((o - KEY_BASE) / 4) as usize;
                self.key_regs[idx] = value;
                // HAL_CRYP_Decrypt's key-derive phase requires the
                // key to be loaded with CRYPEN already on, then
                // ALGOMODE switches to ECB/CBC/CTR while CRYPEN
                // stays on. Re-derive engine.key on every register
                // write so the next block sees the latest bytes.
                if self.engine.enabled {
                    self.engine.key = expand_key(&self.key_regs, self.engine.key_size);
                }
            }
            o if (IV_BASE..=IV_END).contains(&o) => {
                let idx = ((o - IV_BASE) / 4) as usize;
                self.iv_regs[idx] = value;
                // HAL writes IV after enabling CRYPEN (between the
                // AES_KEY and CBC/CTR phases). Push the live IV
                // straight into the engine so chaining picks it up
                // for the upcoming block.
                if self.engine.enabled {
                    self.engine.iv = expand_iv(&self.iv_regs);
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

    fn write_word(p: &mut CrypV1, off: u32, v: u32) {
        p.write(off, 4, v);
    }
    fn read_word(p: &mut CrypV1, off: u32) -> u32 {
        p.read(off, 4)
    }

    /// FIPS-197 Appendix B: AES-128 ECB worked example.
    /// Key   = 2b7e151628aed2a6abf7158809cf4f3c
    /// PT    = 3243f6a8885a308d313198a2e0370734
    /// CT    = 3925841d02dc09fbdc118597196a0b32
    #[test]
    fn aes128_ecb_encrypt_kat() {
        let mut p = CrypV1::new();
        // KEY: 0x2b7e1516 0x28aed2a6 0xabf71588 0x09cf4f3c -> K2LR..K3RR
        write_word(&mut p, 0x30, 0x2b7e1516);
        write_word(&mut p, 0x34, 0x28aed2a6);
        write_word(&mut p, 0x38, 0xabf71588);
        write_word(&mut p, 0x3C, 0x09cf4f3c);

        // CR: AES-ECB encrypt, KEYSIZE=128, DATATYPE=00 (no swap),
        // CRYPEN=1.
        // ALGOMODE = 0b0100 -> bits[5:3] = 0b100; bit18 = 0
        let cr = (0b100 << 3) | CR_CRYPEN;
        write_word(&mut p, 0x00, cr);

        // PT: 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
        write_word(&mut p, 0x08, 0x3243f6a8);
        write_word(&mut p, 0x08, 0x885a308d);
        write_word(&mut p, 0x08, 0x313198a2);
        write_word(&mut p, 0x08, 0xe0370734);

        let c0 = read_word(&mut p, 0x0C);
        let c1 = read_word(&mut p, 0x0C);
        let c2 = read_word(&mut p, 0x0C);
        let c3 = read_word(&mut p, 0x0C);

        assert_eq!(c0, 0x3925841d, "ct[0] mismatch");
        assert_eq!(c1, 0x02dc09fb, "ct[1] mismatch");
        assert_eq!(c2, 0xdc118597, "ct[2] mismatch");
        assert_eq!(c3, 0x196a0b32, "ct[3] mismatch");
    }

    /// AES-128 ECB decrypt is the inverse of the FIPS example.
    #[test]
    fn aes128_ecb_decrypt_kat() {
        let mut p = CrypV1::new();
        write_word(&mut p, 0x30, 0x2b7e1516);
        write_word(&mut p, 0x34, 0x28aed2a6);
        write_word(&mut p, 0x38, 0xabf71588);
        write_word(&mut p, 0x3C, 0x09cf4f3c);

        // ALGODIR=1 (decrypt), AES-ECB
        let cr = (0b100 << 3) | CR_ALGODIR | CR_CRYPEN;
        write_word(&mut p, 0x00, cr);

        write_word(&mut p, 0x08, 0x3925841d);
        write_word(&mut p, 0x08, 0x02dc09fb);
        write_word(&mut p, 0x08, 0xdc118597);
        write_word(&mut p, 0x08, 0x196a0b32);

        assert_eq!(read_word(&mut p, 0x0C), 0x3243f6a8);
        assert_eq!(read_word(&mut p, 0x0C), 0x885a308d);
        assert_eq!(read_word(&mut p, 0x0C), 0x313198a2);
        assert_eq!(read_word(&mut p, 0x0C), 0xe0370734);
    }

    /// NIST SP 800-38A AES-128 CBC encrypt, first block.
    /// Key = 2b7e151628aed2a6abf7158809cf4f3c
    /// IV  = 000102030405060708090a0b0c0d0e0f
    /// PT  = 6bc1bee22e409f96e93d7e117393172a
    /// CT  = 7649abac8119b246cee98e9b12e9197d
    #[test]
    fn aes128_cbc_encrypt_kat_first_block() {
        let mut p = CrypV1::new();
        write_word(&mut p, 0x30, 0x2b7e1516);
        write_word(&mut p, 0x34, 0x28aed2a6);
        write_word(&mut p, 0x38, 0xabf71588);
        write_word(&mut p, 0x3C, 0x09cf4f3c);
        // IV
        write_word(&mut p, 0x40, 0x00010203);
        write_word(&mut p, 0x44, 0x04050607);
        write_word(&mut p, 0x48, 0x08090a0b);
        write_word(&mut p, 0x4C, 0x0c0d0e0f);

        // ALGOMODE=0b0101 -> low=0b101, high=0
        let cr = (0b101 << 3) | CR_CRYPEN;
        write_word(&mut p, 0x00, cr);

        write_word(&mut p, 0x08, 0x6bc1bee2);
        write_word(&mut p, 0x08, 0x2e409f96);
        write_word(&mut p, 0x08, 0xe93d7e11);
        write_word(&mut p, 0x08, 0x7393172a);

        assert_eq!(read_word(&mut p, 0x0C), 0x7649abac);
        assert_eq!(read_word(&mut p, 0x0C), 0x8119b246);
        assert_eq!(read_word(&mut p, 0x0C), 0xcee98e9b);
        assert_eq!(read_word(&mut p, 0x0C), 0x12e9197d);
    }

    /// NIST SP 800-38A AES-128 CTR encrypt, first block.
    /// Key      = 2b7e151628aed2a6abf7158809cf4f3c
    /// CTR init = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    /// PT       = 6bc1bee22e409f96e93d7e117393172a
    /// CT       = 874d6191b620e3261bef6864990db6ce
    #[test]
    fn aes128_ctr_encrypt_kat_first_block() {
        let mut p = CrypV1::new();
        write_word(&mut p, 0x30, 0x2b7e1516);
        write_word(&mut p, 0x34, 0x28aed2a6);
        write_word(&mut p, 0x38, 0xabf71588);
        write_word(&mut p, 0x3C, 0x09cf4f3c);
        write_word(&mut p, 0x40, 0xf0f1f2f3);
        write_word(&mut p, 0x44, 0xf4f5f6f7);
        write_word(&mut p, 0x48, 0xf8f9fafb);
        write_word(&mut p, 0x4C, 0xfcfdfeff);

        // ALGOMODE=0b0110 -> low=0b110, high=0
        let cr = (0b110 << 3) | CR_CRYPEN;
        write_word(&mut p, 0x00, cr);

        write_word(&mut p, 0x08, 0x6bc1bee2);
        write_word(&mut p, 0x08, 0x2e409f96);
        write_word(&mut p, 0x08, 0xe93d7e11);
        write_word(&mut p, 0x08, 0x7393172a);

        assert_eq!(read_word(&mut p, 0x0C), 0x874d6191);
        assert_eq!(read_word(&mut p, 0x0C), 0xb620e326);
        assert_eq!(read_word(&mut p, 0x0C), 0x1bef6864);
        assert_eq!(read_word(&mut p, 0x0C), 0x990db6ce);
    }

    /// AES-128 GCM end-to-end through the v1 register interface,
    /// for AES-128 with K=0, P=16-byte zero, IV=12-byte zero.
    /// Expected (C, T) cross-checked against the `aes-gcm` crate -
    /// see `aes128_gcm_matches_aes_gcm_crate` below.
    #[test]
    fn aes128_gcm_kat_zero_inputs() {
        let mut p = CrypV1::new();

        for off in [0x30, 0x34, 0x38, 0x3C] {
            write_word(&mut p, off, 0);
        }
        write_word(&mut p, 0x40, 0);
        write_word(&mut p, 0x44, 0);
        write_word(&mut p, 0x48, 0);
        write_word(&mut p, 0x4C, 0x00000001);

        let cr_base = CR_ALGOMODE_HI | CR_CRYPEN;
        write_word(&mut p, 0x00, cr_base);            // INIT
        write_word(&mut p, 0x00, cr_base | (1 << 16)); // HEADER
        write_word(&mut p, 0x00, cr_base | (2 << 16)); // PAYLOAD
        for _ in 0..4 {
            write_word(&mut p, 0x08, 0);
        }
        let c0 = read_word(&mut p, 0x0C);
        let c1 = read_word(&mut p, 0x0C);
        let c2 = read_word(&mut p, 0x0C);
        let c3 = read_word(&mut p, 0x0C);
        assert_eq!((c0, c1, c2, c3), (0x0388dace, 0x60b6a392, 0xf328c2b9, 0x71b2fe78));

        write_word(&mut p, 0x00, cr_base | (3 << 16)); // FINAL
        write_word(&mut p, 0x08, 0);
        write_word(&mut p, 0x08, 0);
        write_word(&mut p, 0x08, 0);
        write_word(&mut p, 0x08, 0x00000080);
        let t0 = read_word(&mut p, 0x0C);
        let t1 = read_word(&mut p, 0x0C);
        let t2 = read_word(&mut p, 0x0C);
        let t3 = read_word(&mut p, 0x0C);
        assert_eq!((t0, t1, t2, t3), (0xab6e47d4, 0x2cec13bd, 0xf53a67b2, 0x1257bddf));
    }

    /// Cross-impl reference: the high-level RustCrypto `aes-gcm` crate
    /// must agree byte-for-byte with our peripheral on the same input
    /// (zero key, zero IV, zero plaintext, no AAD).
    #[test]
    fn aes128_gcm_matches_aes_gcm_crate() {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use aes_gcm::{Aes128Gcm, Key, Nonce};
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&[0u8; 16]));
        let mut buf = [0u8; 16];
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&[0u8; 12]), b"", &mut buf)
            .unwrap();
        // Concatenate (C || T) and check against our v1 emitted bytes.
        assert_eq!(&buf[..], &[0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78]);
        assert_eq!(tag.as_slice(), &[0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf]);
    }

    /// AES-256 ECB sanity (FIPS-197 Appendix C.3 KAT).
    /// Key = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    /// PT  = 00112233445566778899aabbccddeeff
    /// CT  = 8ea2b7ca516745bfeafc49904b496089
    #[test]
    fn aes256_ecb_encrypt_kat() {
        let mut p = CrypV1::new();
        write_word(&mut p, 0x20, 0x00010203);
        write_word(&mut p, 0x24, 0x04050607);
        write_word(&mut p, 0x28, 0x08090a0b);
        write_word(&mut p, 0x2C, 0x0c0d0e0f);
        write_word(&mut p, 0x30, 0x10111213);
        write_word(&mut p, 0x34, 0x14151617);
        write_word(&mut p, 0x38, 0x18191a1b);
        write_word(&mut p, 0x3C, 0x1c1d1e1f);

        // KEYSIZE=10 (256), ALGOMODE=AES-ECB (0b0100), CRYPEN
        let cr = (0b100 << 3) | (0b10 << CR_KEYSIZE_SHIFT) | CR_CRYPEN;
        write_word(&mut p, 0x00, cr);

        write_word(&mut p, 0x08, 0x00112233);
        write_word(&mut p, 0x08, 0x44556677);
        write_word(&mut p, 0x08, 0x8899aabb);
        write_word(&mut p, 0x08, 0xccddeeff);

        assert_eq!(read_word(&mut p, 0x0C), 0x8ea2b7ca);
        assert_eq!(read_word(&mut p, 0x0C), 0x516745bf);
        assert_eq!(read_word(&mut p, 0x0C), 0xeafc4990);
        assert_eq!(read_word(&mut p, 0x0C), 0x4b496089);
    }
}
