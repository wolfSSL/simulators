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

pub mod peripheral;
pub mod bus;
pub mod elf;
pub mod cpu;
pub mod runner;

pub use bus::{Bus, MmioRegion};
pub use cpu::{Cpu, CpuStop};
pub use elf::{ElfImage, MemoryRegion};
pub use peripheral::{Peripheral, PeripheralRef};
pub use runner::{ExitCondition, RunOutcome, Runner};
