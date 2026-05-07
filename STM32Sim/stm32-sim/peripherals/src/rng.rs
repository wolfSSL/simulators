/* rng.rs
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

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use stm32_sim_core::peripheral::Peripheral;

/// STM32 RNG peripheral. Register layout is identical across H7/U5/L4:
///   0x00 CR   0x04 SR   0x08 DR
/// On read of DR we always have data ready (DRDY=1) and never report
/// SECS/CECS errors. Optional fixed seeding makes tests deterministic.
pub struct Rng {
    rng: ChaCha20Rng,
    cr: u32,
    sr: u32,
}

impl Rng {
    /// Deterministic seed - good for KAT-style integration tests where
    /// the firmware has to reproduce exact byte streams.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            cr: 0,
            sr: 0,
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

impl Peripheral for Rng {
    fn name(&self) -> &str {
        "rng"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match offset {
            0x00 => self.cr,
            0x04 => self.sr | 0x1, // SR.DRDY
            0x08 => self.rng.next_u32(),
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match offset {
            0x00 => self.cr = value,
            0x04 => self.sr = value & !0x1, // DRDY is RO
            _ => {}
        }
    }
}
