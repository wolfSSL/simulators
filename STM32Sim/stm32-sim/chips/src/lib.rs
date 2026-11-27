/* lib.rs
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

pub mod stm32f417;
pub mod stm32h753;
pub mod stm32mp135;
pub mod stm32u575;

use anyhow::Result;
use stm32_sim_core::{Bus, CpuKind, MemoryRegion};
use stm32_sim_peripherals::RngFault;

/// Run-time knobs that apply to every chip.
#[derive(Debug, Clone, Default)]
pub struct ChipOptions {
    /// Fault to inject into the chip's RNG (`stm32-sim --rng-fault`).
    pub rng_fault: Option<RngFault>,
}

pub struct Chip {
    pub name: &'static str,
    pub cpu_kind: CpuKind,
    pub memory_regions: Vec<MemoryRegion>,
    pub bus: Bus,
}

pub trait ChipBuilder {
    fn build_with(opts: &ChipOptions) -> Result<Chip>;

    fn build() -> Result<Chip> {
        Self::build_with(&ChipOptions::default())
    }
}

pub fn build(name: &str) -> Result<Chip> {
    build_with(name, &ChipOptions::default())
}

pub fn build_with(name: &str, opts: &ChipOptions) -> Result<Chip> {
    match name {
        "stm32f407" => stm32f417::Stm32F407::build_with(opts),
        "stm32f417" => stm32f417::Stm32F417::build_with(opts),
        "stm32h753" => stm32h753::Stm32H753::build_with(opts),
        "stm32u575" => stm32u575::Stm32U575::build_with(opts),
        "stm32u585" => stm32u575::Stm32U585::build_with(opts),
        "stm32mp135" => stm32mp135::Stm32Mp135::build_with(opts),
        other => anyhow::bail!("unknown chip: {other}"),
    }
}

pub fn list() -> &'static [&'static str] {
    &["stm32f407", "stm32f417", "stm32h753", "stm32u575", "stm32u585", "stm32mp135"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_chip_builds() {
        for name in list() {
            let chip = build(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(chip.name, *name);
        }
        assert!(build("stm32f999").is_err());
    }

    #[test]
    fn f417_has_crypto_and_f407_does_not() {
        let has = |chip: &Chip, name: &str| chip.bus.regions.iter().any(|r| r.name == name);
        let f417 = build("stm32f417").unwrap();
        let f407 = build("stm32f407").unwrap();
        for p in ["cryp", "hash", "rng", "rcc", "usart2"] {
            assert!(has(&f417, p), "F417 missing {p}");
        }
        assert!(!has(&f407, "cryp") && !has(&f407, "hash"));
        assert!(has(&f407, "rng"));
    }
}
