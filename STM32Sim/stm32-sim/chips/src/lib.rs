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

pub mod stm32h753;
pub mod stm32mp135;
pub mod stm32u575;

use anyhow::Result;
use stm32_sim_core::{Bus, CpuKind, MemoryRegion};

pub struct Chip {
    pub name: &'static str,
    pub cpu_kind: CpuKind,
    pub memory_regions: Vec<MemoryRegion>,
    pub bus: Bus,
}

pub trait ChipBuilder {
    fn build() -> Result<Chip>;
}

pub fn build(name: &str) -> Result<Chip> {
    match name {
        "stm32h753" => stm32h753::Stm32H753::build(),
        "stm32u575" => stm32u575::Stm32U575::build(),
        "stm32u585" => stm32u575::Stm32U585::build(),
        "stm32mp135" => stm32mp135::Stm32Mp135::build(),
        other => anyhow::bail!("unknown chip: {other}"),
    }
}

pub fn list() -> &'static [&'static str] {
    &["stm32h753", "stm32u575", "stm32u585", "stm32mp135"]
}
