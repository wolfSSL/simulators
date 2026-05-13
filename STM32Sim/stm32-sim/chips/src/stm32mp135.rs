/* stm32mp135.rs
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

//! STM32MP135 - Cortex-A7 single core, no internal flash. Firmware
//! runs from external DDR after an ST-supplied DDR_Init helper has
//! trained the DDR controller. From the simulator's point of view
//! there is no DDR_Init: Unicorn just maps DDR as plain RAM and the
//! ELF loader writes the .text/.data segments straight into it.
//!
//! Memory map (from the MP135 reference manual / CMSIS device
//! headers):
//!   SYSRAM 0x2FFE_0000  128 KiB - lives just below the SRAMs
//!   SRAM1  0x3000_0000   16 KiB
//!   SRAM2  0x3000_4000    8 KiB
//!   SRAM3  0x3000_6000    8 KiB
//!   DDR    0xC000_0000  512 MiB
//!
//! Crypto IP (AHB5 @ 0x5400_0000):
//!   CRYP1 @ 0x5400_2000  - same register layout as the H7 CRYP block;
//!                          wolfSSL's STM32 port aliases CRYP1 -> CRYP.
//!   HASH1 @ 0x5400_3000  - MP13 layout: 4-bit ALGO field at CR[20:17],
//!                          SHA3CFGR register at 0x28, SHA3-224/256/384/512
//!                          plus SHA-384/512 in addition to the legacy
//!                          SHA-1/MD5/SHA-224/SHA-256.
//!   RNG1  @ 0x5400_4000  - identical RNG to the H7/U5.
//!   PKA   @ 0x5400_6000  - U5-generation PKA v2 register file.
//!
//! Other peripherals modelled:
//!   UART4 @ 0x4001_0000  - the F-DK's ST-Link console UART.
//!   RCC   @ 0x5000_0000  - stub; we ignore writes and return zero on
//!                          read because the firmware does not poll
//!                          ready bits in the bare-metal smoke
//!                          configuration.

use anyhow::Result;
use stm32_sim_core::peripheral::wrap;
use stm32_sim_core::{Bus, CpuKind, MemoryRegion};
use stm32_sim_peripherals::{
    cryp::v1::CrypV1, hash::v1::HashV1, pka::v2::PkaV2, usart::StdoutSink, Dbgmcu, Rcc, Rng, Usart,
};

use crate::Chip;

pub struct Stm32Mp135;

impl crate::ChipBuilder for Stm32Mp135 {
    fn build() -> Result<Chip> {
        let memory = vec![
            MemoryRegion {
                base: 0x2FFE_0000,
                size: 0x0002_0000,
                name: "SYSRAM",
            },
            MemoryRegion {
                base: 0x3000_0000,
                size: 0x0000_4000,
                name: "SRAM1",
            },
            MemoryRegion {
                base: 0x3000_4000,
                size: 0x0000_2000,
                name: "SRAM2",
            },
            MemoryRegion {
                base: 0x3000_6000,
                size: 0x0000_2000,
                name: "SRAM3",
            },
            MemoryRegion {
                base: 0xC000_0000,
                size: 0x2000_0000,
                name: "DDR",
            },
        ];

        let mut bus = Bus::new();

        // UART4 - ST-Link console on the MP135F-DK. The H7/U5
        // USART register layout (CR1/BRR/ISR/TDR at the same offsets)
        // is shared by every modern STM32, so we reuse Usart directly.
        let uart4 = wrap(Usart::new("uart4", Box::new(StdoutSink)));
        bus.map(0x4001_0000, 0x0400, "uart4", uart4);

        // RCC stub. The MP135 RCC register layout differs from H7/U5
        // and the wolfcrypt smoke firmware does not poll ready bits
        // (it pokes the crypto peripherals directly without HAL clock
        // gating). A bare register file is enough; if a later HAL-
        // driven firmware needs ready bits, add Rcc::mp13() with the
        // right mask.
        let rcc = wrap(Rcc::raw("rcc-mp13"));
        bus.map(0x5000_0000, 0x1000, "rcc", rcc);

        let cryp1 = wrap(CrypV1::new());
        bus.map(0x5400_2000, 0x0400, "cryp1", cryp1);

        let hash1 = wrap(HashV1::new_mp13());
        bus.map(0x5400_3000, 0x0400, "hash1", hash1);

        let rng1 = wrap(Rng::new());
        bus.map(0x5400_4000, 0x0400, "rng1", rng1);

        // PKA spans 0x2000 like on the U5, since the SRAM-style
        // operand window lives inside the same page block.
        let pka = wrap(PkaV2::new());
        bus.map(0x5400_6000, 0x2000, "pka", pka);

        // DBGMCU at 0x5008_1000. HAL_GetREVID / HAL_GetDEVID read
        // DBGMCU->IDCODE; with the firmware now driving the MP13 HAL
        // (HAL_RCC_OscConfig pokes this on init), the peripheral has
        // to exist or the load faults as READ_UNMAPPED.
        let dbgmcu = wrap(Dbgmcu::mp13());
        bus.map(0x5008_1000, 0x0400, "dbgmcu", dbgmcu);

        Ok(Chip {
            name: "stm32mp135",
            cpu_kind: CpuKind::CortexA,
            memory_regions: memory,
            bus,
        })
    }
}
