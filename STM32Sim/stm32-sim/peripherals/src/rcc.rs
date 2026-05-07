/* rcc.rs
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

use stm32_sim_core::peripheral::Peripheral;

/// Reset and Clock Control. We do not model clock trees; instead we
/// treat the RCC as a 4 KiB scratch register file with a small set of
/// "ready" status bits forced to 1 so STM32Cube HAL polling loops
/// (HSE/HSI/PLL ready, voltage scaling ready) terminate immediately.
///
/// On read, registers behave as a write-back store; on each read, we OR
/// in a chip-supplied "ready mask" for that offset. The chip module
/// configures `ready_mask` to match the STM32 series's CR/PLLCFGR
/// layout. For chips we have not yet specialised, the default mask is
/// applied to the H7-style CR @ 0x00.
pub struct Rcc {
    name: &'static str,
    regs: [u32; 1024],          // 4 KiB / 4 bytes
    ready_offsets: Vec<(u32, u32)>, // (offset, mask) - bits forced high on read
}

impl Rcc {
    /// Construct an RCC with no special ready bits. Suitable for
    /// firmware that pokes registers directly without HAL polling.
    pub fn raw(name: &'static str) -> Self {
        Self {
            name,
            regs: [0u32; 1024],
            ready_offsets: Vec::new(),
        }
    }

    /// STM32H7 RCC ready bits: HSI/HSE/HSI48/PLL1/2/3 ready, VOS ready.
    /// CR @ 0x00, D3CFGR @ 0x130 (VOS).
    pub fn h7() -> Self {
        let mut me = Self::raw("rcc-h7");
        // CR: HSIRDY(2), HSI48RDY(13), CSIRDY(8), HSERDY(17), D1CKRDY(14),
        // D2CKRDY(15), PLL1RDY(25), PLL2RDY(27), PLL3RDY(29).
        me.ready_offsets.push((
            0x00,
            (1 << 2) | (1 << 8) | (1 << 13) | (1 << 14) | (1 << 15)
                | (1 << 17) | (1 << 25) | (1 << 27) | (1 << 29),
        ));
        // PWR D3CR VOSRDY (bit 13) lives in the PWR block; HAL waits for
        // it via PWR not RCC, so PWR peripheral handles it. Nothing
        // here.
        me
    }

    /// STM32U5 RCC ready bits.
    pub fn u5() -> Self {
        let mut me = Self::raw("rcc-u5");
        // CR: MSIS_RDY(2), HSI_RDY(10), HSE_RDY(17), PLL1_RDY(25),
        // PLL2_RDY(27), PLL3_RDY(29), HSI48_RDY(13).
        me.ready_offsets.push((
            0x00,
            (1 << 2) | (1 << 10) | (1 << 13) | (1 << 17)
                | (1 << 25) | (1 << 27) | (1 << 29),
        ));
        me
    }
}

impl Peripheral for Rcc {
    fn name(&self) -> &str {
        self.name
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        let idx = (offset / 4) as usize;
        let base = if idx < self.regs.len() { self.regs[idx] } else { 0 };
        let mut extra = 0u32;
        for (off, mask) in &self.ready_offsets {
            if *off == offset {
                extra |= *mask;
            }
        }
        base | extra
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        let idx = (offset / 4) as usize;
        if idx < self.regs.len() {
            self.regs[idx] = value;
        }
    }
}
