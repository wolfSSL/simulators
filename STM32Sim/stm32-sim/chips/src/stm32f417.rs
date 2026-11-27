/* stm32f417.rs
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
    cryp::v1::CrypV1, hash::v1::HashV1, usart::StdoutSink, Rcc, Rng, Usart,
};

use crate::{Chip, ChipOptions};

/// STM32F417 - Cortex-M4F, 1 MiB flash, 192 KiB SRAM, with the F4
/// crypto block: CRYP (DES/TDES, AES ECB/CBC/CTR; the GCM/CCM modes only
/// arrived with F437/F439), HASH (SHA-1/MD5) and RNG.
///
/// Memory map (RM0090 section 2.3):
///   FLASH   0x0800_0000  1 MiB
///   CCMRAM  0x1000_0000  64 KiB
///   SRAM    0x2000_0000  128 KiB (SRAM1 112 KiB + SRAM2 16 KiB)
///
/// Peripherals:
///   USART2  0x4000_4400   USART3 0x4000_4800   USART1 0x4001_1000
///           (F1/F2/F4 register layout, transmit to stdout)
///   RCC     0x4002_3800
///   FLASH   0x4002_3C00   (interface registers, scratch: ACR latency)
///   CRYP    0x5006_0000
///   HASH    0x5006_0400
///   RNG     0x5006_0800
pub struct Stm32F417;

impl crate::ChipBuilder for Stm32F417 {
    fn build_with(opts: &ChipOptions) -> Result<Chip> {
        build_f4("stm32f417", true, opts)
    }
}

/// STM32F407 - the F417 without CRYP and HASH (the STM32F4DISCOVERY
/// part). Same memory map and RNG.
pub struct Stm32F407;

impl crate::ChipBuilder for Stm32F407 {
    fn build_with(opts: &ChipOptions) -> Result<Chip> {
        build_f4("stm32f407", false, opts)
    }
}

fn build_f4(name: &'static str, crypto: bool, opts: &ChipOptions) -> Result<Chip> {
    let memory = vec![
        MemoryRegion {
            base: 0x0800_0000,
            size: 0x0010_0000,
            name: "FLASH",
        },
        MemoryRegion {
            base: 0x1000_0000,
            size: 0x0001_0000,
            name: "CCMRAM",
        },
        MemoryRegion {
            base: 0x2000_0000,
            size: 0x0002_0000,
            name: "SRAM",
        },
    ];

    let mut bus = Bus::new();

    for (base, uname) in [
        (0x4000_4400, "usart2"),
        (0x4000_4800, "usart3"),
        (0x4001_1000, "usart1"),
    ] {
        let u = wrap(Usart::new_legacy(uname, Box::new(StdoutSink)));
        bus.map(base, 0x0400, uname, u);
    }

    let rcc = wrap(Rcc::f4());
    bus.map(0x4002_3800, 0x0400, "rcc", rcc);

    let flash_if = wrap(Rcc::raw("flash-if"));
    bus.map(0x4002_3C00, 0x0400, "flash-if", flash_if);

    if crypto {
        let cryp = wrap(CrypV1::new_f4());
        bus.map(0x5006_0000, 0x0400, "cryp", cryp);

        let hash = wrap(HashV1::new_f4());
        bus.map(0x5006_0400, 0x0400, "hash", hash);
    }

    let rng = wrap(Rng::new().with_fault(opts.rng_fault));
    bus.map(0x5006_0800, 0x0400, "rng", rng);

    Ok(Chip {
        name,
        cpu_kind: CpuKind::CortexM,
        memory_regions: memory,
        bus,
    })
}
