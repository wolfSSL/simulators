/* cryp/v2.rs
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

//! STM32 U5/H5/H7S "AES" peripheral (HAL v2 / register revision 2).
//! See U5 RM0456 §27. Differs from the H7 v1 CRYP block in:
//!
//! * `CR.CHMOD` is 3 bits at [7:5] (000 ECB, 001 CBC, 010 CTR,
//!   011 GCM, 100 GMAC, 101 CCM) instead of v1's split ALGOMODE.
//! * `CR.MODE` is 2 bits at [4:3] (00 encrypt, 10 decrypt; 01/11 are
//!   key derivation variants we ignore here).
//! * `CR.DATATYPE` is at [2:1] not [7:6].
//! * `CR.KEYSIZE` is a single bit at 18 (0=128, 1=256). v2 does NOT
//!   support 192.
//! * `CR.GCMPH` is at [14:13] not [17:16].
//! * Key registers `KEYR0..KEYR7` go *low to high*; KEYR0 holds the
//!   low 32 bits of the AES key. v1 went the other way.
//! * Register set is more compact (no separate H/L per 64-bit half).

use stm32_sim_core::peripheral::Peripheral;

use super::gcm::{GcmPhase, GcmSession};
use super::{AesMode, CrypEngine, DataType, Direction, KeySize};

const CR: u32 = 0x00;
const SR: u32 = 0x04;
const DINR: u32 = 0x08;
const DOUTR: u32 = 0x0C;
const KEYR0: u32 = 0x10; // ..0x1C = KEYR3 (low 128 bits)
const KEYR_LOW_END: u32 = 0x1C;
const IVR0: u32 = 0x20; // ..0x2C
const IVR_END: u32 = 0x2C;
// On U5 the high half of the AES-256 key occupies a separate
// register block KEYR4..KEYR7 at 0x30-0x3C (NOT 0x40 - that range
// is the suspend regs). Update the offsets and shrink the
// "high-key" window so it doesn't shadow SUSPxR.
const KEYR4: u32 = 0x30; // ..0x3C = KEYR7 (high 128 bits, AES-256 only)
const KEYR_HIGH_END: u32 = 0x3C;
const SUSP_BASE: u32 = 0x40; // SUSP0R..SUSP7R, opaque scratch
const SUSP_END: u32 = 0x5C;
const IER: u32 = 0x300;
const ISR: u32 = 0x304;
const ICR: u32 = 0x308;

// AES_CR layout per stm32u585xx.h:
//   bit 0      EN
//   bits 2:1   DATATYPE
//   bits 4:3   MODE
//   bits 6:5   CHMOD[1:0]
//   bit 16     CHMOD[2]   (3-bit field is split: {bit16, bits[6:5]})
//   bits 14:13 GCMPH
//   bit 18     KEYSIZE
const CR_EN: u32 = 1 << 0;
const CR_DATATYPE_SHIFT: u32 = 1;
const CR_DATATYPE_MASK: u32 = 0x3 << CR_DATATYPE_SHIFT;
const CR_MODE_SHIFT: u32 = 3;
const CR_MODE_MASK: u32 = 0x3 << CR_MODE_SHIFT;
const CR_CHMOD_LOW_SHIFT: u32 = 5;
const CR_CHMOD_LOW_MASK: u32 = 0x3 << CR_CHMOD_LOW_SHIFT;
const CR_CHMOD_HI: u32 = 1 << 16;
const CR_GCMPH_SHIFT: u32 = 13;
const CR_GCMPH_MASK: u32 = 0x3 << CR_GCMPH_SHIFT;
const CR_KEYSIZE_256: u32 = 1 << 18;

const SR_CCF: u32 = 1 << 0;
const ISR_CCF: u32 = 1 << 0;

pub struct CrypV2 {
    cr: u32,
    /// KEYR0..KEYR3 (low 128 bits of key, low-to-high) plus KEYR4..7
    /// (high 128 bits, only used in AES-256). Stored u32-by-u32 in
    /// the same order software writes them.
    key_lo: [u32; 4],
    key_hi: [u32; 4],
    iv_regs: [u32; 4],
    ier: u32,
    isr: u32,
    pub engine: CrypEngine,
    gcm: GcmSession,
    gcm_in_buf: [u8; 16],
    gcm_in_len: usize,
    /// True while CR.MODE is 01/11 (key derivation). HAL_CRYP enables
    /// CRYP in this mode, polls ISR.CCF, then switches to MODE=10
    /// (decrypt) before any DIN/DOUT traffic. We just signal CCF as
    /// soon as the engine enables in this mode.
    key_derivation_active: bool,
}

impl Default for CrypV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl CrypV2 {
    pub fn new() -> Self {
        Self {
            cr: 0,
            key_lo: [0; 4],
            key_hi: [0; 4],
            iv_regs: [0; 4],
            ier: 0,
            isr: 0,
            engine: CrypEngine::default(),
            gcm: GcmSession::default(),
            gcm_in_buf: [0; 16],
            gcm_in_len: 0,
            key_derivation_active: false,
        }
    }

    fn gcm_phase(&self) -> GcmPhase {
        GcmPhase::from_bits((self.cr & CR_GCMPH_MASK) >> CR_GCMPH_SHIFT)
    }

    fn write_cr(&mut self, value: u32) {
        // Mask of CR bits whose change should re-run commit_config()
        // (key bytes / IV bytes are not in CR; GCMPH is its own
        // dedicated path below).
        const CR_ALG_BITS: u32 = CR_DATATYPE_MASK
            | CR_MODE_MASK
            | CR_CHMOD_LOW_MASK
            | CR_CHMOD_HI
            | CR_KEYSIZE_256;

        let was_enabled = self.cr & CR_EN != 0;
        let prev_alg_bits = self.cr & CR_ALG_BITS;
        self.cr = value;

        let now_enabled = self.cr & CR_EN != 0;
        let alg_bits_changed = (self.cr & CR_ALG_BITS) != prev_alg_bits;
        if !was_enabled && now_enabled {
            self.commit_config();
            self.engine.enabled = true;
        } else if was_enabled && !now_enabled {
            self.engine.enabled = false;
            self.key_derivation_active = false;
        } else if now_enabled && self.engine.mode == AesMode::Gcm && !alg_bits_changed {
            // GCM phase-only transition: keep the existing fast path
            // that updates the GCM session without reloading the key.
            let phase = self.gcm_phase();
            if phase == GcmPhase::Init {
                self.gcm.init(&self.engine);
            } else {
                self.gcm.phase = phase;
            }
            self.gcm_in_buf = [0; 16];
            self.gcm_in_len = 0;
            self.engine.reset_fifos();
        } else if now_enabled && alg_bits_changed {
            // HAL paths that flip MODE/CHMOD/KEYSIZE while EN stays
            // high (e.g. AES key-derivation -> decrypt switch). Run
            // a full commit so the engine sees the new config and
            // key_derivation_active is recomputed.
            self.commit_config();
            self.engine.enabled = true;
        }
    }

    fn commit_config(&mut self) {
        self.engine.key_size = if self.cr & CR_KEYSIZE_256 != 0 {
            KeySize::K256
        } else {
            KeySize::K128
        };

        let datatype_bits = (self.cr & CR_DATATYPE_MASK) >> CR_DATATYPE_SHIFT;
        self.engine.datatype = DataType::from_bits(datatype_bits);

        let mode_bits = (self.cr & CR_MODE_MASK) >> CR_MODE_SHIFT;
        // MODE=01/11 = key derivation. HAL uses this to pre-compute
        // inverse round keys before AES ECB/CBC decrypt: enable CRYP,
        // wait CCF, clear CCF, then switch to MODE=10. We don't run a
        // real AES key schedule here - our software AES re-derives on
        // demand - we just mark the phase so compute_isr() can assert
        // CCF immediately.
        self.key_derivation_active = mode_bits == 1 || mode_bits == 3;
        self.engine.direction = match mode_bits {
            0 => Direction::Encrypt,
            2 => Direction::Decrypt,
            _ => Direction::Decrypt, // 01/11 are decrypt-side prep
        };

        let chmod_low = (self.cr & CR_CHMOD_LOW_MASK) >> CR_CHMOD_LOW_SHIFT;
        let chmod_hi = if self.cr & CR_CHMOD_HI != 0 { 1u32 } else { 0 };
        let chmod = chmod_low | (chmod_hi << 2);
        self.engine.mode = match chmod {
            0b000 => AesMode::Ecb,
            0b001 => AesMode::Cbc,
            0b010 => AesMode::Ctr,
            0b011 => AesMode::Gcm,
            other => {
                log::warn!(
                    "CRYP v2: CHMOD 0x{:x} not modelled (we cover ECB/CBC/CTR/GCM)",
                    other
                );
                AesMode::Ecb
            }
        };

        self.engine.key = self.expand_key();
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

    /// On U5/H5, `KEYR0..3` hold the LOW 128 bits of the key, then
    /// `KEYR4..7` the HIGH 128 bits. Within each word the bytes are
    /// big-endian. The full key as a contiguous byte string runs from
    /// KEYR7 (most-significant) down to KEYR0 (least).
    fn expand_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        match self.engine.key_size {
            KeySize::K128 => {
                // 16 bytes from KEYR3..KEYR0 (high to low across regs).
                out[0..4].copy_from_slice(&self.key_lo[3].to_be_bytes());
                out[4..8].copy_from_slice(&self.key_lo[2].to_be_bytes());
                out[8..12].copy_from_slice(&self.key_lo[1].to_be_bytes());
                out[12..16].copy_from_slice(&self.key_lo[0].to_be_bytes());
            }
            KeySize::K192 => {
                // U5 doesn't support AES-192; treat as 128 if it
                // somehow leaks through.
                out[0..4].copy_from_slice(&self.key_lo[3].to_be_bytes());
                out[4..8].copy_from_slice(&self.key_lo[2].to_be_bytes());
                out[8..12].copy_from_slice(&self.key_lo[1].to_be_bytes());
                out[12..16].copy_from_slice(&self.key_lo[0].to_be_bytes());
            }
            KeySize::K256 => {
                // 32 bytes from KEYR7..KEYR0.
                out[0..4].copy_from_slice(&self.key_hi[3].to_be_bytes());
                out[4..8].copy_from_slice(&self.key_hi[2].to_be_bytes());
                out[8..12].copy_from_slice(&self.key_hi[1].to_be_bytes());
                out[12..16].copy_from_slice(&self.key_hi[0].to_be_bytes());
                out[16..20].copy_from_slice(&self.key_lo[3].to_be_bytes());
                out[20..24].copy_from_slice(&self.key_lo[2].to_be_bytes());
                out[24..28].copy_from_slice(&self.key_lo[1].to_be_bytes());
                out[28..32].copy_from_slice(&self.key_lo[0].to_be_bytes());
            }
        }
        out
    }

    fn compute_sr(&self) -> u32 {
        let mut sr = 0;
        if !self.engine.output_empty() || (self.engine.enabled && self.key_derivation_active) {
            sr |= SR_CCF;
        }
        sr
    }

    fn compute_isr(&self) -> u32 {
        // ISR.CCF mirrors SR.CCF on U5; HAL_CRYP polls ISR while
        // older silicon polled SR. We expose both. CCF is also
        // asserted while a key-derivation phase is active so
        // CRYP_WaitOnCCFlag completes.
        let mut isr = 0;
        if !self.engine.output_empty() || (self.engine.enabled && self.key_derivation_active) {
            isr |= ISR_CCF;
        }
        isr
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
            GcmPhase::Init => {}
            GcmPhase::Header => self.gcm.ingest_aad(&block),
            GcmPhase::Payload => {
                let out =
                    self.gcm
                        .process_payload(self.engine.direction, &self.engine, &block);
                self.engine.stage_output(&out);
            }
            GcmPhase::Final => {
                let tag = self.gcm.finalise();
                self.engine.stage_output(&tag);
            }
        }
    }
}

fn expand_iv(regs: &[u32; 4]) -> [u8; 16] {
    // U5/H5 IVR registers: IVR3 holds the most-significant 32 bits of
    // the 128-bit IV (i.e. the first 4 bytes of the IV byte string),
    // IVR0 holds the least-significant. HAL_CRYP::CRYP_SetIV writes
    // pInitVect[0] -> IVR3, pInitVect[3] -> IVR0 (see RM0456 27.4.13).
    // Mirror that: high register first, low register last.
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&regs[3].to_be_bytes());
    out[4..8].copy_from_slice(&regs[2].to_be_bytes());
    out[8..12].copy_from_slice(&regs[1].to_be_bytes());
    out[12..16].copy_from_slice(&regs[0].to_be_bytes());
    out
}

impl Peripheral for CrypV2 {
    fn name(&self) -> &str {
        "cryp-v2"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match offset {
            CR => self.cr,
            SR => self.compute_sr(),
            DINR => 0,
            DOUTR => self.engine.read_dout(),
            o if (KEYR0..=KEYR_LOW_END).contains(&o) => {
                let idx = ((o - KEYR0) / 4) as usize;
                self.key_lo[idx]
            }
            o if (IVR0..=IVR_END).contains(&o) => {
                let idx = ((o - IVR0) / 4) as usize;
                self.iv_regs[idx]
            }
            o if (KEYR4..=KEYR_HIGH_END).contains(&o) => {
                let idx = ((o - KEYR4) / 4) as usize;
                self.key_hi[idx]
            }
            IER => self.ier,
            ISR => self.compute_isr(),
            o if (SUSP_BASE..=SUSP_END).contains(&o) => 0,
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match offset {
            CR => self.write_cr(value),
            DINR => {
                if self.engine.enabled && self.engine.mode == AesMode::Gcm {
                    self.gcm_din(value);
                } else {
                    self.engine.write_din(value);
                }
            }
            o if (KEYR0..=KEYR_LOW_END).contains(&o) => {
                let idx = ((o - KEYR0) / 4) as usize;
                self.key_lo[idx] = value;
                if self.engine.enabled {
                    self.engine.key = self.expand_key();
                }
            }
            o if (IVR0..=IVR_END).contains(&o) => {
                // HAL_CRYP for U5 writes IVRn after AES key-derivation
                // completes, while CRYP is still enabled (see
                // CRYP_AESCBC_Process line 2613). Accept the write
                // regardless of EN and propagate to engine.iv so the
                // next DIN block sees the correct IV.
                let idx = ((o - IVR0) / 4) as usize;
                self.iv_regs[idx] = value;
                self.engine.iv = expand_iv(&self.iv_regs);
            }
            o if (KEYR4..=KEYR_HIGH_END).contains(&o) => {
                let idx = ((o - KEYR4) / 4) as usize;
                self.key_hi[idx] = value;
                if self.engine.enabled {
                    self.engine.key = self.expand_key();
                }
            }
            IER => self.ier = value,
            ICR => self.isr &= !value,
            o if (SUSP_BASE..=SUSP_END).contains(&o) => {
                // SUSPxR is opaque "context save" scratch; accept and
                // ignore.
                let _ = (o, value);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_word(p: &mut CrypV2, off: u32, v: u32) {
        p.write(off, 4, v);
    }
    fn read_word(p: &mut CrypV2, off: u32) -> u32 {
        p.read(off, 4)
    }

    /// FIPS-197 Appendix B AES-128 ECB driven through the U5 v2
    /// register layout. Same math as the v1 KAT - same engine - but
    /// the firmware register sequence is completely different.
    #[test]
    fn aes128_ecb_via_v2_layout() {
        let mut p = CrypV2::new();
        // KEYR3 (high) .. KEYR0 (low) for 16-byte key.
        write_word(&mut p, 0x10, 0x09cf4f3c); // KEYR0 = key[12..15]
        write_word(&mut p, 0x14, 0xabf71588); // KEYR1 = key[8..11]
        write_word(&mut p, 0x18, 0x28aed2a6); // KEYR2 = key[4..7]
        write_word(&mut p, 0x1C, 0x2b7e1516); // KEYR3 = key[0..3]

        // CR: CHMOD=000 (ECB), MODE=00 (encrypt), DATATYPE=00 (word),
        // KEYSIZE=128 (bit 18 clear), EN=1.
        let cr = CR_EN;
        write_word(&mut p, 0x00, cr);

        // Plaintext: 16 BE bytes via DIN
        write_word(&mut p, 0x08, 0x3243f6a8);
        write_word(&mut p, 0x08, 0x885a308d);
        write_word(&mut p, 0x08, 0x313198a2);
        write_word(&mut p, 0x08, 0xe0370734);

        assert_eq!(read_word(&mut p, 0x0C), 0x3925841d);
        assert_eq!(read_word(&mut p, 0x0C), 0x02dc09fb);
        assert_eq!(read_word(&mut p, 0x0C), 0xdc118597);
        assert_eq!(read_word(&mut p, 0x0C), 0x196a0b32);
    }

    /// AES-256 ECB through v2 (KEYSIZE=1).
    #[test]
    fn aes256_ecb_via_v2_layout() {
        let mut p = CrypV2::new();
        // 32-byte FIPS-197 C.3 key, packed into KEYR7..KEYR0.
        // Key: 000102...1f
        write_word(&mut p, 0x10, 0x1c1d1e1f); // KEYR0 = bytes 28..31
        write_word(&mut p, 0x14, 0x18191a1b); // KEYR1
        write_word(&mut p, 0x18, 0x14151617); // KEYR2
        write_word(&mut p, 0x1C, 0x10111213); // KEYR3
        // U5 KEYR4..7 live at 0x30..0x3C (after IVRn), not 0x40 -
        // 0x40+ is the SUSPxR scratch area.
        write_word(&mut p, 0x30, 0x0c0d0e0f); // KEYR4 = bytes 12..15
        write_word(&mut p, 0x34, 0x08090a0b); // KEYR5
        write_word(&mut p, 0x38, 0x04050607); // KEYR6
        write_word(&mut p, 0x3C, 0x00010203); // KEYR7 = bytes 0..3

        let cr = CR_KEYSIZE_256 | CR_EN;
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

    /// CTR mode through the v2 CHMOD encoding (010).
    #[test]
    fn aes128_ctr_via_v2_layout() {
        let mut p = CrypV2::new();
        write_word(&mut p, 0x10, 0x09cf4f3c);
        write_word(&mut p, 0x14, 0xabf71588);
        write_word(&mut p, 0x18, 0x28aed2a6);
        write_word(&mut p, 0x1C, 0x2b7e1516);
        // IV per HAL convention: IVR3 = first 4 bytes of IV, IVR0 = last.
        // NIST CTR IV bytes: f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,fa,fb,fc,fd,fe,ff.
        write_word(&mut p, 0x20, 0xfcfdfeff); // IVR0 = last 4 bytes
        write_word(&mut p, 0x24, 0xf8f9fafb); // IVR1
        write_word(&mut p, 0x28, 0xf4f5f6f7); // IVR2
        write_word(&mut p, 0x2C, 0xf0f1f2f3); // IVR3 = first 4 bytes

        // CHMOD=010 (CTR)
        let cr = (0b010 << CR_CHMOD_LOW_SHIFT) | CR_EN;
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

    /// HAL_CRYP ECB/CBC decrypt prelude: MODE=01 (key derivation),
    /// EN=1, then poll ISR.CCF. The simulator must assert CCF
    /// immediately so CRYP_WaitOnCCFlag returns. After the HAL clears
    /// CCF and switches to MODE=10, CCF must drop back to 0 (no DOUT
    /// has been produced yet).
    #[test]
    fn aes256_keyderiv_completes_immediately() {
        let mut p = CrypV2::new();

        // 32-byte key in KEYR7..KEYR0 (any value; the engine doesn't
        // actually run AES during key derivation).
        for (off, w) in [
            (0x10, 0x1c1d1e1fu32),
            (0x14, 0x18191a1b),
            (0x18, 0x14151617),
            (0x1C, 0x10111213),
            (0x30, 0x0c0d0e0f),
            (0x34, 0x08090a0b),
            (0x38, 0x04050607),
            (0x3C, 0x00010203),
        ] {
            write_word(&mut p, off, w);
        }

        // CR = KEYSIZE=256 | CHMOD=001 (CBC) | MODE=01 (key deriv) | EN=1
        let cr_keyderiv = CR_KEYSIZE_256
            | (0b001 << CR_CHMOD_LOW_SHIFT)
            | (1u32 << CR_MODE_SHIFT)
            | CR_EN;
        write_word(&mut p, 0x00, cr_keyderiv);

        // ISR.CCF must be set without any DIN write.
        assert_eq!(read_word(&mut p, 0x304) & 0x1, 0x1);
        // SR.CCF mirrors it.
        assert_eq!(read_word(&mut p, 0x04) & 0x1, 0x1);

        // HAL clears CCF and switches to MODE=10 (decrypt). Algorithm
        // bits changed while EN stayed high, so commit_config reruns
        // and key_derivation_active clears.
        write_word(&mut p, 0x308, 0x1); // ICR
        let cr_decrypt = CR_KEYSIZE_256
            | (0b001 << CR_CHMOD_LOW_SHIFT)
            | (2u32 << CR_MODE_SHIFT)
            | CR_EN;
        write_word(&mut p, 0x00, cr_decrypt);

        // No DIN/DOUT yet - CCF should be clear.
        assert_eq!(read_word(&mut p, 0x304) & 0x1, 0x0);
        assert_eq!(read_word(&mut p, 0x04) & 0x1, 0x0);
    }

    /// GCM through v2 (CHMOD=011, GCMPH at bits[14:13]). Same
    /// expected tag as the v1 GCM KAT.
    #[test]
    fn aes128_gcm_via_v2_layout() {
        let mut p = CrypV2::new();
        for off in [0x10, 0x14, 0x18, 0x1C] {
            write_word(&mut p, off, 0);
        }
        // J0 (IV with counter padding) per HAL convention: 96-bit zero
        // IV plus counter 0x00000001 in the low 32 bits, written
        // pInitVect[0] -> IVR3, pInitVect[3] -> IVR0. The counter
        // word is the LSB of J0, so it lives in IVR0.
        write_word(&mut p, 0x20, 0x00000001); // IVR0 = counter
        write_word(&mut p, 0x24, 0);
        write_word(&mut p, 0x28, 0);
        write_word(&mut p, 0x2C, 0);

        let cr_base = (0b011 << CR_CHMOD_LOW_SHIFT) | CR_EN;
        // INIT (GCMPH = 00)
        write_word(&mut p, 0x00, cr_base);
        // HEADER (01)
        write_word(&mut p, 0x00, cr_base | (1 << CR_GCMPH_SHIFT));
        // PAYLOAD (10)
        write_word(&mut p, 0x00, cr_base | (2 << CR_GCMPH_SHIFT));
        for _ in 0..4 {
            write_word(&mut p, 0x08, 0);
        }
        let c = (0..4).map(|_| read_word(&mut p, 0x0C)).collect::<Vec<_>>();
        assert_eq!(c, vec![0x0388dace, 0x60b6a392, 0xf328c2b9, 0x71b2fe78]);
        // FINAL (11)
        write_word(&mut p, 0x00, cr_base | (3 << CR_GCMPH_SHIFT));
        write_word(&mut p, 0x08, 0);
        write_word(&mut p, 0x08, 0);
        write_word(&mut p, 0x08, 0);
        write_word(&mut p, 0x08, 0x00000080);
        let t = (0..4).map(|_| read_word(&mut p, 0x0C)).collect::<Vec<_>>();
        assert_eq!(t, vec![0xab6e47d4, 0x2cec13bd, 0xf53a67b2, 0x1257bddf]);
    }
}
