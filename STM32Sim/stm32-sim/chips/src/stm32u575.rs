/* stm32u575.rs
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

//! STM32U575 - Cortex-M33, Trustzone-capable, 2 MiB flash, ~768 KiB
//! SRAM split across SRAM1/2/3/4. Hardware crypto: AES (v2), SAES,
//! HASH (v2 with SHA-384/512), RNG, PKA (v2).
//!
//! This is the second chip target after H7. The interesting thing
//! about wiring U5 *and* H7 in the same simulator is that almost
//! nothing in `core/` or the shared engine modules has to change -
//! only the per-chip base-address map and the per-revision register
//! adapters (CrypV2, HashV2). That's the abstraction the user asked
//! for "extendable to simulate other STM32 chips with different
//! hardware accelerator revisions."

use anyhow::Result;
use stm32_sim_core::peripheral::wrap;
use stm32_sim_core::{Bus, MemoryRegion};
use stm32_sim_peripherals::{
    cryp::v2::CrypV2, hash::v1::HashV1, pka::v2::PkaV2, usart::StdoutSink, Dbgmcu, Rcc, Rng, Usart,
};

use crate::Chip;

pub struct Stm32U575;

impl crate::ChipBuilder for Stm32U575 {
    fn build() -> Result<Chip> {
        let memory = vec![
            MemoryRegion {
                base: 0x0800_0000,
                size: 0x0020_0000,
                name: "FLASH",
            },
            // U5 SRAM1+2+3 contiguous from 0x2000_0000.
            MemoryRegion {
                base: 0x2000_0000,
                size: 0x000C_0000,
                name: "SRAM",
            },
            // U5 backup SRAM (SRAM4).
            MemoryRegion {
                base: 0x2807_0000,
                size: 0x0000_4000,
                name: "BKP_SRAM",
            },
        ];

        let mut bus = Bus::new();

        // USART1 at 0x4001_3800 - the U5 debug console. We reuse the
        // same Usart model; both H7 and U5 share the H7-style register
        // layout with TDR @ 0x28.
        let usart1 = wrap(Usart::new("usart1", Box::new(StdoutSink)));
        bus.map(0x4001_3800, 0x0400, "usart1", usart1);

        // RCC at 0x4602_0C00 (AHB3 secure on U5).
        let rcc = wrap(Rcc::u5());
        bus.map(0x4602_0C00, 0x0400, "rcc", rcc);

        // Crypto block (AHB2, non-secure aliases per stm32u5xx.h):
        //   AES  @ 0x420C_0000
        //   HASH @ 0x420C_0400  (uses same CR layout as H7 - bits 7,18
        //                        for ALGO - so we re-use HashV1)
        //   RNG  @ 0x420C_0800
        //   SAES @ 0x420C_0C00  (not modelled)
        //   PKA  @ 0x420C_2000
        let aes = wrap(CrypV2::new());
        bus.map(0x420C_0000, 0x0400, "aes", aes);

        // U5 HASH ALGO field is at bits {18, 17}, not {18, 7} like
        // H7. Use the U5-layout constructor.
        let hash = wrap(HashV1::new_u5());
        bus.map(0x420C_0400, 0x0400, "hash", hash);

        let rng = wrap(Rng::new());
        bus.map(0x420C_0800, 0x0400, "rng", rng);

        let pka = wrap(PkaV2::new());
        bus.map(0x420C_2000, 0x2000, "pka", pka);

        // DBGMCU on U5 lives at 0xE004_4000 (system region). HAL
        // queries IDCODE for revision-gated workarounds.
        let dbgmcu = wrap(Dbgmcu::u5());
        bus.map(0xE004_4000, 0x0400, "dbgmcu", dbgmcu);

        Ok(Chip {
            name: "stm32u575",
            memory_regions: memory,
            bus,
        })
    }
}

/// STM32U585 - Cortex-M33 Trustzone, like U575 but with the full
/// crypto suite enabled in CMSIS/HAL: AES + HASH + PKA on top of the
/// RNG/SAES that U575 already exposes. For our simulator the
/// peripheral set is the same (we model both AES and HASH and PKA
/// regardless), so this is just a name alias for now.
pub struct Stm32U585;

impl crate::ChipBuilder for Stm32U585 {
    fn build() -> Result<Chip> {
        let mut chip = Stm32U575::build()?;
        chip.name = "stm32u585";
        Ok(chip)
    }
}
