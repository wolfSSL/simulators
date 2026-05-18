/* stm32h753.rs
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

use anyhow::Result;
use stm32_sim_core::peripheral::wrap;
use stm32_sim_core::{Bus, CpuKind, MemoryRegion};
use stm32_sim_peripherals::{
    cryp::v1::CrypV1, hash::v1::HashV1, usart::StdoutSink, Dbgmcu, Rcc, Rng, Usart,
};

use crate::Chip;

/// STM32H753 - Cortex-M7, 2 MiB flash, 1 MiB SRAM (split DTCM/AXI/SRAM).
///
/// Memory map (matches the Renode reference firmware linker script):
///   FLASH    0x0800_0000  2 MiB
///   DTCM     0x2000_0000  128 KiB
///   AXI_SRAM 0x2400_0000  512 KiB
///   SRAM1    0x3000_0000  128 KiB (mapped for HAL DMA buffers)
///
/// Peripheral pages we model today:
///   USART3 @ 0x4000_4800     (page 0x4000_4000)
///   RCC    @ 0x5802_4400     (page 0x5802_4000)
///   CRYP/HASH/RNG @ 0x4802_1000-0x4802_1FFF  (RNG only at this stage)
pub struct Stm32H753;

impl crate::ChipBuilder for Stm32H753 {
    fn build() -> Result<Chip> {
        let memory = vec![
            MemoryRegion {
                base: 0x0800_0000,
                size: 0x0020_0000,
                name: "FLASH",
            },
            MemoryRegion {
                base: 0x2000_0000,
                size: 0x0002_0000,
                name: "DTCM",
            },
            MemoryRegion {
                base: 0x2400_0000,
                size: 0x0008_0000,
                name: "AXI_SRAM",
            },
            MemoryRegion {
                base: 0x3000_0000,
                size: 0x0002_0000,
                name: "SRAM1",
            },
        ];

        let mut bus = Bus::new();

        let usart3 = wrap(Usart::new("usart3", Box::new(StdoutSink)));
        bus.map(0x4000_4800, 0x0400, "usart3", usart3);

        let rcc = wrap(Rcc::h7());
        bus.map(0x5802_4400, 0x0400, "rcc", rcc);

        let cryp = wrap(CrypV1::new());
        bus.map(0x4802_1000, 0x0400, "cryp", cryp);

        let hash = wrap(HashV1::new());
        bus.map(0x4802_1400, 0x0400, "hash", hash);

        let rng = wrap(Rng::new());
        bus.map(0x4802_1800, 0x0400, "rng", rng);

        // DBGMCU @ 0x5C00_1000 - HAL reads IDCODE for revision-gated
        // work-arounds (HAL_GetREVID inside HAL_CRYP_Init).
        let dbgmcu = wrap(Dbgmcu::h7());
        bus.map(0x5C00_1000, 0x0400, "dbgmcu", dbgmcu);

        Ok(Chip {
            name: "stm32h753",
            cpu_kind: CpuKind::CortexM,
            memory_regions: memory,
            bus,
        })
    }
}
