/* lib.rs
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

pub mod pic32mz_ec;
pub mod pic32mz_ef;

use anyhow::Result;
use pic32mz_sim_core::{Bus, MemoryRegion};

pub struct Chip {
    pub name: &'static str,
    pub memory_regions: Vec<MemoryRegion>,
    pub bus: Bus,
}

pub fn build(name: &str) -> Result<Chip> {
    match name {
        "pic32mz2048ech144" | "ec" => pic32mz_ec::build(),
        "pic32mz2048efh144" | "ef" => pic32mz_ef::build(),
        other => anyhow::bail!("unknown chip: {other}"),
    }
}

pub fn list() -> &'static [&'static str] {
    &["pic32mz2048ech144", "pic32mz2048efh144"]
}
