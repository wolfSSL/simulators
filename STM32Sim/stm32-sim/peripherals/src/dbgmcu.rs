/* dbgmcu.rs
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

//! DBGMCU stub. STM32 HAL drivers occasionally read `DBGMCU->IDCODE`
//! to gate revision-specific work-arounds (e.g. HAL_GetREVID() inside
//! HAL_CRYP for AES-192 key handling on early H7 silicon). The
//! peripheral's only job here is to keep those reads from raising a
//! READ_UNMAPPED fault; we hand back a plausible IDCODE for the
//! target chip.

use stm32_sim_core::peripheral::Peripheral;

/// IDCODE register layout: bits[11:0] = DEV_ID, bits[31:16] = REV_ID.
const IDC: u32 = 0x000;

pub struct Dbgmcu {
    name: &'static str,
    /// Value returned from IDCODE reads.
    idcode: u32,
    /// Catch-all backing for whatever the HAL writes (e.g. CR for the
    /// stop / sleep modes).
    regs: [u32; 256],
}

impl Dbgmcu {
    /// STM32H753: DEV_ID = 0x450, REV_ID = 0x1003 ("rev V"). The
    /// specific REV_ID rarely matters for HAL gating, but we pick a
    /// value HAL recognises as a real chip rev.
    pub fn h7() -> Self {
        Self {
            name: "dbgmcu",
            idcode: (0x1003 << 16) | 0x450,
            regs: [0; 256],
        }
    }

    /// STM32U575: DEV_ID = 0x482, REV_ID = 0x1000.
    pub fn u5() -> Self {
        Self {
            name: "dbgmcu",
            idcode: (0x1000 << 16) | 0x482,
            regs: [0; 256],
        }
    }
}

impl Peripheral for Dbgmcu {
    fn name(&self) -> &str {
        self.name
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        if offset == IDC {
            return self.idcode;
        }
        let idx = (offset / 4) as usize;
        if idx < self.regs.len() {
            self.regs[idx]
        } else {
            0
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        let idx = (offset / 4) as usize;
        if idx < self.regs.len() {
            self.regs[idx] = value;
        }
    }
}
