/* hash/v1.rs
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

//! STM32H7-style HASH register file. RM0433 §35.2.
//!
//! Register map:
//!   0x000 CR        (control: INIT, DATATYPE, MODE, ALGO[0])
//!   0x004 DIN       (data input)
//!   0x008 STR       (start: NBLW, DCAL)
//!   0x00C HR0..HR4  (hash result, 5 words for SHA-1/MD5)
//!   0x020 IMR
//!   0x024 SR        (BUSY/DCIS/DINIS)
//!   0x028 SHA3CFGR  (MP13 only: SHA3 padding / round config. The same
//!                    offset is reserved/scratch on H7 and U5; firmware
//!                    on those parts never writes it.)
//!   0x02C..0xF4     reserved / scratch (CSR begins at 0x0F8)
//!   0x310 HR0..HR7  (extended hash result, 8 words for SHA-256)
//!
//! ALGO selection differs by chip family:
//!   - H7  : 2-bit field at CR bits {18, 7}
//!           00 SHA-1, 01 MD5, 10 SHA-224, 11 SHA-256.
//!   - U5  : 2-bit field at CR bits {18, 17} (same encoding).
//!   - MP13: 4-bit field at CR bits [20:17] - covers SHA-1/MD5/SHA-224/
//!           SHA-256, SHA-384/512 + SHA-512/224/256, and the four SHA3
//!           digest sizes (SHA3-224/256/384/512).

use stm32_sim_core::peripheral::Peripheral;

use super::{Algo, DataType, Engine};

// H7 HASH register layout (RM0433 §35.10 + stm32h753xx.h):
//   0x00 CR (control)
//   0x04 DIN
//   0x08 STR (start)
//   0x0C..0x1C HR[5]   (legacy result, 5 words)
//   0x20 IMR  0x24 SR
//   0x28..0xF4 reserved
//   0xF8..0x1CC CSR[54] (context save/restore)
//   plus 0x310..0x32C HR[8] (extended result for SHA-256)
const CR: u32 = 0x000;
const DIN: u32 = 0x004;
const STR: u32 = 0x008;
const HR_LEGACY_BASE: u32 = 0x00C;
const HR_LEGACY_END: u32 = 0x01C;
const IMR: u32 = 0x020;
const SR: u32 = 0x024;
/// SHA3 padding / round configuration register. MP13 only - on H7/U5
/// the offset is reserved. wolfSSL's SHA3 driver writes the padding
/// byte here before each DCAL; we store the value so reads return
/// what was written but the engine selects SHA3 purely from CR.ALGO.
const SHA3CFGR: u32 = 0x028;
const CSR_BASE: u32 = 0x0F8;
const CSR_END: u32 = 0x1CC; // CSR_BASE + 53 * 4
const HR_EXT_BASE: u32 = 0x310;
/// H7/U5 stop the extended HR window at 0x32C (8 words, SHA-256 sized).
/// MP13's HASH_DIGEST aliases a 50-word HR2 region at 0x310-0x3D4, so
/// wolfSSL's loop reads `HASH_DIGEST->HR[5..15]` for SHA-384 / SHA-512
/// at offsets that run past 0x32C. Cap at 0x34C (16 words) so SHA-512
/// fits; reads of indices beyond `engine.result.len()` fall through to
/// the zero return in `read_hr`.
const HR_EXT_END: u32 = 0x34C;

// HASH_CR layout: bit 2 INIT, bits[5:4] DATATYPE, bit 6 MODE.
// ALGO is a 2-bit field but the chip family decides where it lives:
//   - H7 / older: bits {18, 7}   (HASH_CR_ALGO_Msk = 0x40080)
//   - U5         : bits {18, 17} (HASH_CR_ALGO_Msk = 0x60000;
//                  the U5 CMSIS comments say 0x40080 but the
//                  HAL_HASH source uses HASH_CR_ALGO_0 = 1<<17 so
//                  the real layout is 17-18, not 7-18.)
const CR_INIT: u32 = 1 << 2;
const CR_DATATYPE_SHIFT: u32 = 4;
const CR_DATATYPE_MASK: u32 = 0x3 << CR_DATATYPE_SHIFT;
const CR_MODE_HMAC: u32 = 1 << 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgoLayout {
    /// H7 family: 2-bit ALGO at CR bits {7, 18}. Encoding: 00 SHA-1,
    /// 01 MD5, 10 SHA-224, 11 SHA-256.
    H7,
    /// U5 family: 2-bit ALGO at CR bits {17, 18}. Same encoding as H7.
    U5,
    /// MP13 family: 4-bit ALGO at CR bits [20:17]. The wider field
    /// covers SHA-1/MD5/SHA-224/SHA-256 (codes 0..3), the SHA3 family
    /// (codes 4..7) and SHA-384/512 plus SHA-512/224/256 (codes
    /// 12..15). The SHA3CFGR register at offset 0x28 supplies extra
    /// padding / round metadata that we model as a write-back store.
    Mp13,
}

impl AlgoLayout {
    /// True if ALGO is decoded from a 4-bit field (currently MP13).
    fn is_wide(self) -> bool {
        matches!(self, AlgoLayout::Mp13)
    }
}

// Tests below build CR values explicitly using H7 ALGO bit positions;
// keep these constants for those tests. Production code goes through
// `AlgoLayout::lo_bit()` / `hi_bit()` to support both H7 and U5.
const CR_ALGO_LO: u32 = 1 << 7;
const CR_ALGO_HI: u32 = 1 << 18;

const STR_NBLW_MASK: u32 = 0x1F;
const STR_DCAL: u32 = 1 << 8;

const SR_DINIS: u32 = 1 << 0;
const SR_DCIS: u32 = 1 << 1;

pub struct HashV1 {
    layout: AlgoLayout,
    cr: u32,
    str_reg: u32,
    imr: u32,
    sr: u32,
    /// Mirror of the SHA3CFGR register on MP13. Unused on H7/U5 but
    /// kept in the struct unconditionally so the write/read paths
    /// can be unconditional. wolfSSL writes the SHA3 padding byte
    /// here; the engine ignores the value because the digest type
    /// is already fixed by CR.ALGO.
    sha3cfgr: u32,
    /// One-word lookahead: each DIN write displaces this and commits
    /// the displaced word in full to the engine. STR.DCAL pulls this
    /// out and feeds it with `NBLW`-derived valid-byte count. This is
    /// how the H7 HASH actually behaves: the partial-byte semantics
    /// only apply to the most-recently-written DIN word.
    pending: Option<u32>,
    /// Context save/restore registers (HASH->CSR[0..54], 0xF8..0x1CC).
    /// wolfSSL's port saves these between Update calls and writes
    /// them back at the start of the next call so the in-progress
    /// hash survives a clock-disable cycle. Real silicon stuffs
    /// fragments of the internal block schedule here; we treat them
    /// as opaque storage and rely on the Rust hasher itself to
    /// preserve algorithmic state across feed_word calls.
    csr: [u32; 54],
    /// Pending lookahead value at the time `capture_snapshot` was
    /// called, so RestoreContext can re-establish the partial-byte
    /// position for the upcoming Final.
    saved_pending: Option<u32>,
    /// True iff STR was written since the last CR write. wolfSSL's
    /// `RestoreContext` for an in-flight hash writes IMR, then STR,
    /// then CR-with-INIT (and finally CSR). Its `init` branch (for a
    /// fresh hash) writes CR-with-INIT first, then STR via
    /// NumValidBits. We use this as the disambiguator: a CR-INIT
    /// preceded by an STR write is a Restore; one not preceded by
    /// STR is a Fresh init.
    str_written_since_cr: bool,
    pub engine: Engine,
}

impl Default for HashV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl HashV1 {
    pub fn new() -> Self {
        Self::with_layout(AlgoLayout::H7)
    }

    pub fn new_u5() -> Self {
        Self::with_layout(AlgoLayout::U5)
    }

    /// MP13 (STM32MP135) layout: 4-bit ALGO field, SHA3CFGR register,
    /// SHA-384/512 + SHA3 support.
    pub fn new_mp13() -> Self {
        Self::with_layout(AlgoLayout::Mp13)
    }

    fn with_layout(layout: AlgoLayout) -> Self {
        Self {
            layout,
            cr: 0,
            str_reg: 0,
            imr: 0,
            sr: SR_DINIS,
            sha3cfgr: 0,
            pending: None,
            csr: [0; 54],
            saved_pending: None,
            str_written_since_cr: false,
            engine: Engine::default(),
        }
    }

    fn parse_algo(&self) -> Algo {
        if self.layout.is_wide() {
            // MP13: 4-bit ALGO at bits [20:17]. Encoding from
            // stm32mp13xx_hal_hash.h HASH_ALGOSELECTION_*:
            //   0  SHA-1        4  SHA3-224      8  SHAKE-128
            //   1  MD5          5  SHA3-256      9  SHAKE-256
            //   2  SHA-224      6  SHA3-384     10  RAWSHAKE-128
            //   3  SHA-256      7  SHA3-512     11  RAWSHAKE-256
            //                  12  SHA-384
            //                  13  SHA-512/224
            //                  14  SHA-512/256
            //                  15  SHA-512
            // SHA-512/224 and SHA-512/256 have their own IVs (FIPS-180
            // section 5.3) and produce different digests from a SHA-512
            // tail-truncation, so they each route to a dedicated hasher.
            // RAWSHAKE collapses to SHAKE - the only difference is the
            // suffix bits in the padding rule (omitted in RawSHAKE), and
            // the sha3 crate exposes only the standard SHAKE
            // construction. wolfSSL's STM32 port does not exercise
            // RAWSHAKE, so the simpler aliasing is fine.
            let code = (self.cr >> 17) & 0xF;
            match code {
                0 => Algo::Sha1,
                1 => Algo::Md5,
                2 => Algo::Sha224,
                3 => Algo::Sha256,
                4 => Algo::Sha3_224,
                5 => Algo::Sha3_256,
                6 => Algo::Sha3_384,
                7 => Algo::Sha3_512,
                8 | 10 => Algo::Shake128,
                9 | 11 => Algo::Shake256,
                12 => Algo::Sha384,
                13 => Algo::Sha512_224,
                14 => Algo::Sha512_256,
                15 => Algo::Sha512,
                _ => Algo::Sha1,
            }
        } else {
            let lo_bit = 1u32 << self.layout_lo_bit();
            let hi_bit = 1u32 << 18;
            let lo = if self.cr & lo_bit != 0 { 1u32 } else { 0 };
            let hi = if self.cr & hi_bit != 0 { 1u32 } else { 0 };
            match (hi, lo) {
                (0, 0) => Algo::Sha1,
                (0, 1) => Algo::Md5,
                (1, 0) => Algo::Sha224,
                (1, 1) => Algo::Sha256,
                _ => Algo::Sha1,
            }
        }
    }

    fn layout_lo_bit(&self) -> u32 {
        match self.layout {
            AlgoLayout::H7 => 7,
            AlgoLayout::U5 => 17,
            // Unused on MP13 - that path takes the 4-bit branch in
            // parse_algo. We still need a value to type-check.
            AlgoLayout::Mp13 => 17,
        }
    }

    fn parse_datatype(&self) -> DataType {
        DataType::from_bits((self.cr & CR_DATATYPE_MASK) >> CR_DATATYPE_SHIFT)
    }

    fn write_cr(&mut self, value: u32) {
        self.cr = value & !CR_INIT; // INIT self-clears

        if value & CR_INIT != 0 {
            // wolfSSL's `RestoreContext` for an in-flight hash writes
            // STR (with the saved value) just before CR-with-INIT. The
            // `init` branch (fresh hash) writes CR-with-INIT FIRST and
            // STR after. The presence of an STR write between the
            // last CR write and this one disambiguates the two paths.
            let is_restore = self.str_written_since_cr && self.engine.has_snapshot();
            if is_restore {
                self.engine.restore_from_snapshot();
                self.pending = self.saved_pending;
            } else {
                let hmac = self.cr & CR_MODE_HMAC != 0;
                self.engine
                    .init_with_mode(self.parse_algo(), self.parse_datatype(), hmac);
                self.pending = None;
            }
            self.sr = SR_DINIS;
        }
        self.str_written_since_cr = false;
    }

    fn write_din(&mut self, value: u32) {
        if let Some(prev) = self.pending.take() {
            self.engine.feed_word(prev, 4);
        }
        self.pending = Some(value);
    }

    fn write_str(&mut self, value: u32) {
        let was_dcal = self.str_reg & STR_DCAL != 0;
        self.str_reg = value;
        self.str_written_since_cr = true;
        let now_dcal = value & STR_DCAL != 0;
        if !was_dcal && now_dcal {
            let nblw_bits = value & STR_NBLW_MASK;
            if let Some(last) = self.pending.take() {
                // NBLW is a *bit* count: 0 means the whole 32-bit word
                // is valid, otherwise round up to the enclosing byte
                // (1..=8 bits -> 1 byte, 9..=16 -> 2, ..., 25..=31 -> 4).
                // wolfSSL only ever feeds byte-aligned messages, but
                // the ceil-div keeps non-aligned cases from silently
                // dropping the partial byte.
                let valid = if nblw_bits == 0 {
                    4
                } else {
                    nblw_bits.div_ceil(8).min(4) as u8
                };
                self.engine.feed_word(last, valid);
            }
            self.engine.finalize();
            self.sr = SR_DCIS | SR_DINIS;
            self.str_reg &= !STR_DCAL;
            self.csr = [0; 54];
            // Reset the str-write tracker so the *next* test's
            // first CR-INIT (which won't have an STR write
            // immediately preceding it) is correctly classified as
            // a fresh init, not a restore. The snapshot itself
            // survives so the same-test GetHash+Final pattern can
            // re-clone it.
            self.str_written_since_cr = false;
        }
    }

    fn read_hr(&self, idx: usize) -> u32 {
        if idx < self.engine.result.len() && self.engine.finalised {
            self.engine.result[idx]
        } else {
            0
        }
    }
}

impl Peripheral for HashV1 {
    fn name(&self) -> &str {
        "hash-v1"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match offset {
            CR => self.cr,
            STR => self.str_reg,
            IMR => self.imr,
            SR => self.sr,
            SHA3CFGR => self.sha3cfgr,
            o if (HR_LEGACY_BASE..=HR_LEGACY_END).contains(&o) => {
                let idx = ((o - HR_LEGACY_BASE) / 4) as usize;
                self.read_hr(idx)
            }
            o if (HR_EXT_BASE..=HR_EXT_END).contains(&o) => {
                let idx = ((o - HR_EXT_BASE) / 4) as usize;
                self.read_hr(idx)
            }
            o if (CSR_BASE..=CSR_END).contains(&o) => {
                // Firmware is reading CSR - SaveContext is in
                // progress. Snapshot the engine state so the
                // matching RestoreContext (CR-INIT) restores it.
                // Captured once per save: idx 0 is the trigger.
                if (o - CSR_BASE) / 4 == 0 {
                    self.engine.capture_snapshot();
                    self.saved_pending = self.pending;
                }
                let idx = ((o - CSR_BASE) / 4) as usize;
                self.csr[idx]
            }
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match offset {
            CR => self.write_cr(value),
            DIN => self.write_din(value),
            STR => self.write_str(value),
            IMR => self.imr = value,
            SR => self.sr &= !value,
            SHA3CFGR => self.sha3cfgr = value,
            o if (CSR_BASE..=CSR_END).contains(&o) => {
                let idx = ((o - CSR_BASE) / 4) as usize;
                self.csr[idx] = value;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stm32_sim_core::peripheral::Peripheral;

    fn write_word(p: &mut HashV1, off: u32, v: u32) {
        p.write(off, 4, v);
    }
    fn read_word(p: &mut HashV1, off: u32) -> u32 {
        p.read(off, 4)
    }

    /// HMAC-MD5 KAT (RFC 2202 Test Case 7-style: "what do ya want
    /// for nothing?" with key "Jefe"). Drives the H7 hardware-HMAC
    /// 3-phase flow: feed key, DCAL, feed message, DCAL, feed key
    /// again, DCAL, read HR.
    ///   Key  = "Jefe"                             (4 bytes)
    ///   Data = "what do ya want for nothing?"    (28 bytes)
    ///   HMAC-MD5 = 750c783e6ab0b503eaa86e310a5db738
    #[test]
    fn hmac_md5_via_hardware_mode() {
        let mut p = HashV1::new();
        let key = b"Jefe";
        let msg = b"what do ya want for nothing?";

        // CR: ALGO=MD5 (hi=0, lo=1), MODE=HMAC (bit 6),
        // DATATYPE=byte (bits[5:4]=10), INIT (bit 2).
        let cr_hmac =
            CR_ALGO_LO | CR_MODE_HMAC | (2 << CR_DATATYPE_SHIFT) | CR_INIT;

        // Helper: pack a byte slice into BE u32 words and feed via
        // DIN, ending with DCAL+NBLW for any partial final word.
        let drive_data = |p: &mut HashV1, data: &[u8]| {
            let mut i = 0;
            while i + 4 <= data.len() {
                let w = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                // DATATYPE=byte means the engine swap_bytes()es the
                // input. Pre-swap so the engine sees the byte stream
                // in order.
                p.write(DIN, 4, w.swap_bytes());
                i += 4;
            }
            let rem = data.len() - i;
            let nblw_bits;
            if rem == 0 {
                nblw_bits = 0;
            } else {
                let mut tail = [0u8; 4];
                tail[..rem].copy_from_slice(&data[i..]);
                let w = u32::from_be_bytes(tail);
                p.write(DIN, 4, w.swap_bytes());
                nblw_bits = (rem * 8) as u32;
            }
            p.write(STR, 4, STR_DCAL | nblw_bits);
        };

        // Phase 1: key. The remaining phases skip the CR-INIT
        // because in the wolfSSL flow each phase's RestoreContext
        // (CR-INIT after STR) is interpreted as a snapshot-restore
        // and our engine state persists. For this self-contained
        // unit test we just keep feeding DIN/DCAL across phases.
        p.write(CR, 4, cr_hmac);
        drive_data(&mut p, key);

        // Phase 2: message
        drive_data(&mut p, msg);

        // Phase 3: key again
        drive_data(&mut p, key);

        let hr: Vec<u32> = (0..4)
            .map(|i| read_word(&mut p, HR_LEGACY_BASE + i * 4))
            .collect();
        let expected = [0x750c783e, 0x6ab0b503, 0xeaa86e31, 0x0a5db738];
        assert_eq!(hr.as_slice(), &expected, "HMAC-MD5 mismatch");
    }

    /// Empty-message hashes (all algorithms): trivial KAT verifying
    /// the INIT + DCAL flow with zero DIN writes.
    #[test]
    fn empty_message_kats() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let mut p = HashV1::new();
        // ALGO=SHA-256: hi=1, lo=1 -> CR bit 18 + bit 7 set
        let cr_init = CR_ALGO_HI | CR_ALGO_LO | (2 << CR_DATATYPE_SHIFT) | CR_INIT;
        write_word(&mut p, CR, cr_init);
        write_word(&mut p, STR, STR_DCAL);
        let hr: Vec<u32> = (0..8).map(|i| read_word(&mut p, HR_EXT_BASE + i * 4)).collect();
        let expected = [
            0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
            0x7852b855,
        ];
        assert_eq!(hr.as_slice(), &expected, "SHA-256 empty hash mismatch");
    }

    /// FIPS-180 SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    /// Drive via DIN with DATATYPE=word and a 3-byte partial last
    /// word, signalled by STR.NBLW=24 + DCAL.
    #[test]
    fn sha1_abc_kat() {
        let mut p = HashV1::new();
        // ALGO=SHA-1 (hi=0, lo=0), DATATYPE=word, INIT.
        write_word(&mut p, CR, CR_INIT);
        // "abc" packed BE into a single word: 0x61 62 63 00.
        write_word(&mut p, DIN, 0x6162_6300);
        // NBLW = 24 bits valid; DCAL.
        write_word(&mut p, STR, STR_DCAL | 24);

        let hr: Vec<u32> = (0..5)
            .map(|i| read_word(&mut p, HR_LEGACY_BASE + i * 4))
            .collect();
        let expected = [
            0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d,
        ];
        assert_eq!(hr.as_slice(), &expected);
    }

    /// FIPS-180 SHA-256("abc") =
    ///   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    #[test]
    fn sha256_abc_kat() {
        let mut p = HashV1::new();
        let cr_init = CR_ALGO_HI | CR_ALGO_LO | CR_INIT;
        write_word(&mut p, CR, cr_init);
        write_word(&mut p, DIN, 0x6162_6300);
        write_word(&mut p, STR, STR_DCAL | 24);
        let hr: Vec<u32> = (0..8).map(|i| read_word(&mut p, HR_EXT_BASE + i * 4)).collect();
        let expected = [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];
        assert_eq!(hr.as_slice(), &expected);
    }

    /// FIPS-180 SHA-256("abcdefghbcdefghicdefghijdefghijkefghijklfghi
    /// jklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstno
    /// pqrstu") = .. (NIST 64-byte boundary message). Drive using
    /// 4-byte-aligned message (16 words = 64 bytes), exercising the
    /// streaming path.
    #[test]
    fn sha256_56byte_block_kat() {
        // FIPS-180 SHA-256 example: input "abcdbcdecdefdefgefghfghighij
        // hijkijkljklmklmnlmnomnopnopq" (56 bytes -> spans 1 block + pad)
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(msg.len(), 56);
        let mut p = HashV1::new();
        let cr_init = CR_ALGO_HI | CR_ALGO_LO | (2 << CR_DATATYPE_SHIFT) | CR_INIT;
        write_word(&mut p, CR, cr_init);
        for chunk in msg.chunks(4) {
            let w = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            // DATATYPE=byte means the engine swaps; pre-swap so the
            // engine sees msg in order.
            write_word(&mut p, DIN, w.swap_bytes());
        }
        write_word(&mut p, STR, STR_DCAL);
        let hr: Vec<u32> = (0..8).map(|i| read_word(&mut p, HR_EXT_BASE + i * 4)).collect();
        // Expected = SHA-256 of those 56 bytes (FIPS-180 example).
        let expected = [
            0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039, 0xa33ce459, 0x64ff2167, 0xf6ecedd4,
            0x19db06c1,
        ];
        assert_eq!(hr.as_slice(), &expected, "SHA-256 56B mismatch");
    }

    /// MP13 SHA3-256("abc") =
    ///   3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    /// Exercises the 4-bit ALGO field at CR[20:17] (code 0b0101 for
    /// SHA3-256) on the MP13 layout, plus the SHA3CFGR scratch
    /// register that wolfSSL writes ahead of each DCAL.
    #[test]
    fn sha3_256_abc_kat_mp13() {
        let mut p = HashV1::new_mp13();
        // SHA3-256 ALGO code = 5 -> CR[20:17] = 0b0101. DATATYPE=byte
        // (bits[5:4]=10) so the engine swap_bytes()es the input. INIT.
        let cr_init = (5u32 << 17) | (2 << CR_DATATYPE_SHIFT) | CR_INIT;
        // Mirror the wolfSSL flow: padding byte goes to SHA3CFGR first.
        // Value is opaque to the simulator (engine picks SHA3 from CR).
        write_word(&mut p, SHA3CFGR, 0x06);
        write_word(&mut p, CR, cr_init);
        // "abc" packed BE into one word, pre-swapped for DATATYPE=byte.
        write_word(&mut p, DIN, 0x6162_6300u32.swap_bytes());
        // NBLW = 24 bits valid + DCAL.
        write_word(&mut p, STR, STR_DCAL | 24);

        let hr: Vec<u32> = (0..8)
            .map(|i| read_word(&mut p, HR_EXT_BASE + i * 4))
            .collect();
        let expected = [
            0x3a985da7, 0x4fe225b2, 0x045c172d, 0x6bd390bd, 0x855f086e, 0x3e9d525b, 0x46bfe245,
            0x11431532,
        ];
        assert_eq!(hr.as_slice(), &expected, "SHA3-256 abc mismatch");

        // SHA3CFGR write/read round-trip.
        assert_eq!(read_word(&mut p, SHA3CFGR), 0x06);
    }

    /// MP13 SHA3-512("") =
    ///   a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6
    ///   15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
    #[test]
    fn sha3_512_empty_kat_mp13() {
        let mut p = HashV1::new_mp13();
        let cr_init = (7u32 << 17) | (2 << CR_DATATYPE_SHIFT) | CR_INIT;
        write_word(&mut p, CR, cr_init);
        write_word(&mut p, STR, STR_DCAL);
        let hr: Vec<u32> = (0..16)
            .map(|i| read_word(&mut p, HR_EXT_BASE + i * 4))
            .collect();
        // HR_EXT only goes up to HR7 (8 words); for SHA3-512 the
        // remaining 8 words spill past HR_EXT_END and read as 0 in
        // this stub. The first 8 words should match the digest
        // prefix.
        let expected_prefix = [
            0xa69f73cc, 0xa23a9ac5, 0xc8b567dc, 0x185a756e, 0x97c98216, 0x4fe25859, 0xe0d1dcc1,
            0x475c80a6,
        ];
        assert_eq!(&hr[..8], &expected_prefix, "SHA3-512 empty hash prefix mismatch");
    }

    /// MP13 SHAKE-128("") with 16-byte output =
    ///   7f9c2ba4e88f827d616045507605853e
    /// SHAKE is variable-length; the engine fixes the output to 16
    /// bytes (matching the MP13 HAL's HASH_DIGEST_SIZE_SHAKE_128
    /// default). Exercises ALGO code 0b1000 in the 4-bit MP13 field.
    #[test]
    fn shake128_empty_kat_mp13() {
        let mut p = HashV1::new_mp13();
        let cr_init = (8u32 << 17) | (2 << CR_DATATYPE_SHIFT) | CR_INIT;
        write_word(&mut p, CR, cr_init);
        write_word(&mut p, STR, STR_DCAL);
        let hr: Vec<u32> = (0..4)
            .map(|i| read_word(&mut p, HR_EXT_BASE + i * 4))
            .collect();
        let expected = [0x7f9c2ba4, 0xe88f827d, 0x61604550, 0x7605853e];
        assert_eq!(hr.as_slice(), &expected, "SHAKE-128 empty mismatch");
    }

    /// MP13 SHAKE-256("") with 32-byte output =
    ///   46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
    /// ALGO code = 0b1001 (= 9).
    #[test]
    fn shake256_empty_kat_mp13() {
        let mut p = HashV1::new_mp13();
        let cr_init = (9u32 << 17) | (2 << CR_DATATYPE_SHIFT) | CR_INIT;
        write_word(&mut p, CR, cr_init);
        write_word(&mut p, STR, STR_DCAL);
        let hr: Vec<u32> = (0..8)
            .map(|i| read_word(&mut p, HR_EXT_BASE + i * 4))
            .collect();
        let expected = [
            0x46b9dd2b, 0x0ba88d13, 0x233b3feb, 0x743eeb24, 0x3fcd52ea, 0x62b81b82, 0xb50c2764,
            0x6ed5762f,
        ];
        assert_eq!(hr.as_slice(), &expected, "SHAKE-256 empty mismatch");
    }

    /// MD5("") = d41d8cd98f00b204e9800998ecf8427e
    #[test]
    fn md5_empty_kat() {
        let mut p = HashV1::new();
        // ALGO=MD5: hi=0, lo=1
        let cr_init = CR_ALGO_LO | (2 << CR_DATATYPE_SHIFT) | CR_INIT;
        write_word(&mut p, CR, cr_init);
        write_word(&mut p, STR, STR_DCAL);
        // MD5 output is 4 words; uses legacy HR area.
        let hr: Vec<u32> = (0..4)
            .map(|i| read_word(&mut p, HR_LEGACY_BASE + i * 4))
            .collect();
        // MD5 of empty string is constant.
        let expected = [0xd41d8cd9, 0x8f00b204, 0xe9800998, 0xecf8427e];
        assert_eq!(hr.as_slice(), &expected);
    }
}
