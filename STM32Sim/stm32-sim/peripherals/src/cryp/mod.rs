/* cryp/mod.rs
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

//! Shared cipher engine for the STM32 CRYP peripheral.
//!
//! The register-shape adapter (v1 = F4/H7 HAL v1, v2 = U5 HAL v2) is in
//! per-revision modules. This module owns the actual cryptographic
//! state (key, IV, FIFOs) and the per-block transform: AES (16-byte
//! blocks) on every revision, plus DES / TDES (8-byte blocks) on the v1
//! CRYP found in F2/F4/F7/H7.

pub mod gcm;
pub mod v1;
pub mod v2;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use des::{Des, TdesEde3};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySize {
    K128,
    K192,
    K256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    Ecb,
    Cbc,
    Ctr,
    Gcm,
    /// AES "key derivation" mode (algomode 0b0111). On real H7 silicon
    /// this triggers an internal computation of the inverse round
    /// keys for the upcoming decrypt. Software writes a few DIN words
    /// to indicate the key schedule it wants and waits BUSY=0.
    /// We have a software AES that derives round keys lazily inside
    /// `aes::Aes*::decrypt_block`, so we just need to absorb (and
    /// silently discard) any DIN that arrives during this phase.
    KeyDerivation,
    /// DES-ECB (v1 ALGOMODE 0b0010). Key K1.
    DesEcb,
    /// DES-CBC (v1 ALGOMODE 0b0011). Key K1, IV IV0.
    DesCbc,
    /// TDES-ECB (v1 ALGOMODE 0b0000). Keys K1/K2/K3, EDE.
    TdesEcb,
    /// TDES-CBC (v1 ALGOMODE 0b0001). Keys K1/K2/K3, IV IV0.
    TdesCbc,
}

impl AesMode {
    /// Cipher block length in bytes: 8 for DES/TDES, 16 for AES.
    pub fn block_len(self) -> usize {
        match self {
            AesMode::DesEcb | AesMode::DesCbc | AesMode::TdesEcb | AesMode::TdesCbc => 8,
            _ => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

/// CR.DATATYPE: how the engine swaps incoming/outgoing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    /// 00 - no swap
    Word,
    /// 01 - 16-bit halfword swap
    Halfword,
    /// 10 - 8-bit byte swap (the wolfSSL default)
    Byte,
    /// 11 - bit swap
    Bit,
}

impl DataType {
    pub fn from_bits(bits: u32) -> Self {
        match bits & 0x3 {
            0 => DataType::Word,
            1 => DataType::Halfword,
            2 => DataType::Byte,
            _ => DataType::Bit,
        }
    }

    /// Apply the swap to a 32-bit register value as the AES engine
    /// would see it on the wire. STM32 CRYP uses a single DATATYPE for
    /// both DIN and DOUT.
    pub fn swap(self, v: u32) -> u32 {
        match self {
            DataType::Word => v,
            DataType::Halfword => v.rotate_right(16),
            DataType::Byte => v.swap_bytes(),
            DataType::Bit => {
                // Reverse bits within each byte; STM32 then byte-swaps.
                let mut out: u32 = 0;
                for i in 0..4 {
                    let b = ((v >> (i * 8)) & 0xFF) as u8;
                    out |= (b.reverse_bits() as u32) << ((3 - i) * 8);
                }
                out
            }
        }
    }
}

/// Stateful CRYP engine: an input FIFO that triggers a block transform
/// once it holds one cipher block (16 bytes AES, 8 bytes DES/TDES) and an
/// output FIFO drained by DOUT reads.
pub struct CrypEngine {
    pub key: [u8; 32],
    /// DES / TDES key material K1 || K2 || K3 (DES uses K1 only).
    pub des_key: [u8; 24],
    pub iv: [u8; 16],
    pub key_size: KeySize,
    pub mode: AesMode,
    pub direction: Direction,
    pub datatype: DataType,
    pub enabled: bool,
    in_buf: [u8; 16],
    in_len: usize,
    out_buf: [u8; 16],
    out_pos: usize,
    out_avail: usize,
}

impl Default for CrypEngine {
    fn default() -> Self {
        Self {
            key: [0; 32],
            des_key: [0; 24],
            iv: [0; 16],
            key_size: KeySize::K128,
            mode: AesMode::Ecb,
            direction: Direction::Encrypt,
            datatype: DataType::Word,
            enabled: false,
            in_buf: [0; 16],
            in_len: 0,
            out_buf: [0; 16],
            out_pos: 0,
            out_avail: 0,
        }
    }
}

impl CrypEngine {
    pub fn reset_fifos(&mut self) {
        self.in_buf = [0; 16];
        self.in_len = 0;
        self.out_buf = [0; 16];
        self.out_pos = 0;
        self.out_avail = 0;
    }

    pub fn input_full(&self) -> bool {
        self.in_len >= self.mode.block_len()
    }
    pub fn input_empty(&self) -> bool {
        self.in_len == 0
    }
    pub fn output_empty(&self) -> bool {
        self.out_avail == 0
    }
    pub fn output_full(&self) -> bool {
        self.out_avail == self.mode.block_len()
    }

    /// Push one DIN word. Triggers a block transform when the FIFO
    /// holds one cipher block.
    pub fn write_din(&mut self, value: u32) {
        let block_len = self.mode.block_len();
        if !self.enabled || self.in_len >= block_len {
            return;
        }
        let swapped = self.datatype.swap(value);
        let bytes = swapped.to_be_bytes();
        for b in bytes {
            self.in_buf[self.in_len] = b;
            self.in_len += 1;
        }
        if self.in_len == block_len {
            self.process_block();
        }
    }

    /// Pop one DOUT word.
    pub fn read_dout(&mut self) -> u32 {
        if self.out_avail < 4 {
            return 0;
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.out_buf[self.out_pos..self.out_pos + 4]);
        self.out_pos += 4;
        self.out_avail -= 4;
        let raw = u32::from_be_bytes(buf);
        self.datatype.swap(raw)
    }

    fn process_block(&mut self) {
        let mut block = self.in_buf;
        let mut emit = true;
        match self.mode {
            AesMode::Ecb => {
                self.aes_block(&mut block);
            }
            AesMode::Cbc => match self.direction {
                Direction::Encrypt => {
                    for i in 0..16 {
                        block[i] ^= self.iv[i];
                    }
                    self.aes_block(&mut block);
                    self.iv = block;
                }
                Direction::Decrypt => {
                    let prev_iv = self.iv;
                    self.iv = block;
                    self.aes_block(&mut block);
                    for i in 0..16 {
                        block[i] ^= prev_iv[i];
                    }
                }
            },
            AesMode::Ctr => {
                let mut keystream = self.iv;
                self.aes_encrypt_block(&mut keystream);
                for i in 0..16 {
                    block[i] ^= keystream[i];
                }
                ctr_inc(&mut self.iv);
            }
            AesMode::Gcm => {
                // GCM block processing happens in the per-revision
                // adapter (it owns the phase machine). The engine only
                // exposes raw AES via aes_encrypt_block_external.
                emit = false;
            }
            AesMode::KeyDerivation => {
                // H7 hardware uses this phase to compute inverse round
                // keys; software waits BUSY=0 and ignores DOUT. Drop
                // the input block on the floor.
                emit = false;
            }
            AesMode::DesEcb | AesMode::TdesEcb => {
                let mut b8 = [0u8; 8];
                b8.copy_from_slice(&block[..8]);
                self.des_block(&mut b8);
                block[..8].copy_from_slice(&b8);
            }
            AesMode::DesCbc | AesMode::TdesCbc => {
                let mut b8 = [0u8; 8];
                b8.copy_from_slice(&block[..8]);
                match self.direction {
                    Direction::Encrypt => {
                        for i in 0..8 {
                            b8[i] ^= self.iv[i];
                        }
                        self.des_block(&mut b8);
                        self.iv[..8].copy_from_slice(&b8);
                    }
                    Direction::Decrypt => {
                        let mut prev_iv = [0u8; 8];
                        prev_iv.copy_from_slice(&self.iv[..8]);
                        self.iv[..8].copy_from_slice(&b8);
                        self.des_block(&mut b8);
                        for i in 0..8 {
                            b8[i] ^= prev_iv[i];
                        }
                    }
                }
                block[..8].copy_from_slice(&b8);
            }
        }
        if emit {
            self.out_buf = block;
            self.out_pos = 0;
            self.out_avail = self.mode.block_len();
        }
        self.in_buf = [0; 16];
        self.in_len = 0;
    }

    /// Expose raw AES-encrypt for outer machinery (GCM phase machine).
    pub fn aes_encrypt_external(&self, block: &mut [u8; 16]) {
        self.aes_encrypt_block(block);
    }

    /// Stage `bytes` (must be 16) into the output FIFO. Used by the
    /// GCM phase machine to emit ciphertext / tag through DOUT.
    pub fn stage_output(&mut self, bytes: &[u8; 16]) {
        self.out_buf = *bytes;
        self.out_pos = 0;
        self.out_avail = 16;
    }

    /// DES or TDES (EDE with K1/K2/K3) on one 8-byte block, in the
    /// selected direction.
    fn des_block(&self, block: &mut [u8; 8]) {
        let arr = GenericArray::from_mut_slice(block);
        let tdes = matches!(self.mode, AesMode::TdesEcb | AesMode::TdesCbc);
        match (tdes, self.direction) {
            (false, Direction::Encrypt) => {
                Des::new(GenericArray::from_slice(&self.des_key[..8])).encrypt_block(arr)
            }
            (false, Direction::Decrypt) => {
                Des::new(GenericArray::from_slice(&self.des_key[..8])).decrypt_block(arr)
            }
            (true, Direction::Encrypt) => {
                TdesEde3::new(GenericArray::from_slice(&self.des_key)).encrypt_block(arr)
            }
            (true, Direction::Decrypt) => {
                TdesEde3::new(GenericArray::from_slice(&self.des_key)).decrypt_block(arr)
            }
        }
    }

    /// Apply the AES round selected by `direction` to `block` in place.
    fn aes_block(&self, block: &mut [u8; 16]) {
        match self.direction {
            Direction::Encrypt => self.aes_encrypt_block(block),
            Direction::Decrypt => self.aes_decrypt_block(block),
        }
    }

    fn aes_encrypt_block(&self, block: &mut [u8; 16]) {
        let arr = GenericArray::from_mut_slice(block);
        match self.key_size {
            KeySize::K128 => {
                let cipher = Aes128::new(GenericArray::from_slice(&self.key[..16]));
                cipher.encrypt_block(arr);
            }
            KeySize::K192 => {
                let cipher = Aes192::new(GenericArray::from_slice(&self.key[..24]));
                cipher.encrypt_block(arr);
            }
            KeySize::K256 => {
                let cipher = Aes256::new(GenericArray::from_slice(&self.key[..32]));
                cipher.encrypt_block(arr);
            }
        }
    }

    fn aes_decrypt_block(&self, block: &mut [u8; 16]) {
        let arr = GenericArray::from_mut_slice(block);
        match self.key_size {
            KeySize::K128 => {
                let cipher = Aes128::new(GenericArray::from_slice(&self.key[..16]));
                cipher.decrypt_block(arr);
            }
            KeySize::K192 => {
                let cipher = Aes192::new(GenericArray::from_slice(&self.key[..24]));
                cipher.decrypt_block(arr);
            }
            KeySize::K256 => {
                let cipher = Aes256::new(GenericArray::from_slice(&self.key[..32]));
                cipher.decrypt_block(arr);
            }
        }
    }
}

/// 128-bit big-endian counter increment used by AES-CTR.
fn ctr_inc(iv: &mut [u8; 16]) {
    for i in (0..16).rev() {
        iv[i] = iv[i].wrapping_add(1);
        if iv[i] != 0 {
            break;
        }
    }
}
