/* rng.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of PIC32MZSim.
 *
 * PIC32MZSim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * PIC32MZSim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

use pic32mz_sim_core::{MemBus, Peripheral};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// PIC32MZ RNG block at physical base 0x1F88_6000 (KSEG1 alias
/// 0xBF88_6000). Register layout matches the PIC32MZ EF family data
/// sheet "Random Number Generator" chapter. Each register has the
/// standard PIC32 atomic SET/CLR/INV aliases at +4/+8/+0xC.
///
///   0x00 RNGCON
///   0x10 RNGPOLY1     0x20 RNGPOLY2
///   0x30 RNGNUMGEN1   0x40 RNGNUMGEN2
///   0x50 RNGSEED1     0x60 RNGSEED2
///   0x70 RNGCNT
///
/// RNGCON bits used by wolfSSL (random.c:4051-4078):
///   bit 8  TRNGMODE  - select TRNG mode for the seed source.
///   bit 9  TRNGEN    - enable TRNG entropy collection.
///   bit 10 PRNGEN    - enable the LFSR PRNG that outputs through
///                      RNGNUMGEN1/2.
///   bit 11 LOAD      - load RNGSEED1/2 into the LFSR state.
///   bit 14..18 PLEN  - polynomial length (we accept any value).
///
/// Behaviour:
///   - When TRNG is enabled (bit 8 + bit 9 set), `RNGCNT` ramps up to
///     64 over a few ticks so the wolfSSL `while (RNGCNT < 64)` loop
///     terminates.
///   - Reads of RNGNUMGEN1/RNGNUMGEN2 pull two u32s from a seeded
///     ChaCha20 (deterministic for CI reproducibility; identical seed
///     across runs unless `with_seed` is overridden by the chip
///     config).
///   - RNGSEED1/RNGSEED2/RNGPOLY1/RNGPOLY2 are stored but not used:
///     the actual entropy output is the ChaCha20 stream regardless of
///     what the firmware loaded into the LFSR. This is intentional -
///     reproducing the on-silicon LFSR exactly is not necessary for
///     wolfSSL CI, which only cares that random.c returns nonzero
///     bytes that pass its sanity checks.
pub struct Rng {
    rng: ChaCha20Rng,
    rngcon: u32,
    rngseed1: u32,
    rngseed2: u32,
    rngpoly1: u32,
    rngpoly2: u32,
    rngcnt: u32,
}

impl Rng {
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            rngcon: 0,
            rngseed1: 0,
            rngseed2: 0,
            rngpoly1: 0,
            rngpoly2: 0,
            rngcnt: 0,
        }
    }

    pub fn new() -> Self {
        Self::with_seed(0xDEAD_BEEF_CAFE_BABE)
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

// PIC32MZ RNG register layout: each SFR occupies a 16-byte slot to
// make room for the SET/CLR/INV atomic aliases at +4/+8/+0xC.
const RNGCON_OFF: u32 = 0x00;
const RNGPOLY1_OFF: u32 = 0x10;
const RNGPOLY2_OFF: u32 = 0x20;
const RNGNUMGEN1_OFF: u32 = 0x30;
const RNGNUMGEN2_OFF: u32 = 0x40;
const RNGSEED1_OFF: u32 = 0x50;
const RNGSEED2_OFF: u32 = 0x60;
const RNGCNT_OFF: u32 = 0x70;

const TRNGMODE: u32 = 1 << 8;
const TRNGEN: u32 = 1 << 9;
const LOAD: u32 = 1 << 11;

fn atomic_op(current: u32, lane: u32, value: u32) -> u32 {
    match lane {
        0 => value,
        1 => current | value,
        2 => current & !value,
        3 => current ^ value,
        _ => current,
    }
}

fn split_atomic(offset: u32, base: u32) -> Option<u32> {
    let delta = offset.wrapping_sub(base);
    if delta < 16 {
        Some(delta >> 2)
    } else {
        None
    }
}

impl Peripheral for Rng {
    fn name(&self) -> &str {
        "rng"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        if let Some(lane) = split_atomic(offset, RNGCON_OFF) {
            if lane == 0 {
                // Auto-clear the LOAD bit one read after the firmware
                // sets it - real silicon clears it within a few cycles
                // once the seed is latched into the LFSR. Without this
                // the wolfSSL init spins forever on
                // `while (RNGCONbits.LOAD == 1)`.
                let v = self.rngcon;
                self.rngcon &= !LOAD;
                return v;
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, RNGSEED1_OFF) {
            if lane == 0 {
                return self.rngseed1;
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, RNGSEED2_OFF) {
            if lane == 0 {
                return self.rngseed2;
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, RNGNUMGEN1_OFF) {
            if lane == 0 {
                return self.rng.next_u32();
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, RNGNUMGEN2_OFF) {
            if lane == 0 {
                return self.rng.next_u32();
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, RNGPOLY1_OFF) {
            if lane == 0 {
                return self.rngpoly1;
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, RNGPOLY2_OFF) {
            if lane == 0 {
                return self.rngpoly2;
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, RNGCNT_OFF) {
            if lane == 0 {
                // Advance the entropy counter when TRNG is running so
                // the firmware's `while (RNGCNT < 64)` loop exits.
                if (self.rngcon & (TRNGMODE | TRNGEN)) == (TRNGMODE | TRNGEN) && self.rngcnt < 64 {
                    self.rngcnt = (self.rngcnt + 4).min(64);
                }
                return self.rngcnt;
            }
            return 0;
        }
        0
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32, _mem: &mut dyn MemBus) {
        if let Some(lane) = split_atomic(offset, RNGCON_OFF) {
            let new = atomic_op(self.rngcon, lane, value);
            // Disabling TRNG resets the counter.
            if (new & TRNGEN) == 0 {
                self.rngcnt = 0;
            }
            self.rngcon = new;
            return;
        }
        if let Some(lane) = split_atomic(offset, RNGSEED1_OFF) {
            self.rngseed1 = atomic_op(self.rngseed1, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, RNGSEED2_OFF) {
            self.rngseed2 = atomic_op(self.rngseed2, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, RNGPOLY1_OFF) {
            self.rngpoly1 = atomic_op(self.rngpoly1, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, RNGPOLY2_OFF) {
            self.rngpoly2 = atomic_op(self.rngpoly2, lane, value);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pic32mz_sim_core::NullMemBus;

    #[test]
    fn trng_counter_ramps_when_enabled() {
        let mut r = Rng::with_seed(1);
        let mut mem = NullMemBus;
        r.write(RNGCON_OFF, 4, TRNGMODE | TRNGEN, &mut mem);
        let mut last = 0;
        for _ in 0..32 {
            last = r.read(RNGCNT_OFF, 4);
            if last >= 64 {
                break;
            }
        }
        assert!(last >= 64, "RNGCNT never reached 64 (got {last})");
    }

    #[test]
    fn numgen_returns_distinct_words() {
        let mut r = Rng::with_seed(1);
        let a = r.read(RNGNUMGEN1_OFF, 4);
        let b = r.read(RNGNUMGEN1_OFF, 4);
        assert_ne!(a, b, "consecutive RNGNUMGEN1 reads should differ");
    }
}
