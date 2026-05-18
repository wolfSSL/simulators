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

pub mod peripheral;
pub mod bus;
pub mod elf;
pub mod cpu;
pub mod runner;
pub mod mem;

pub use bus::{Bus, MmioRegion};
pub use cpu::{Cpu, CpuStop};
pub use elf::{ElfImage, MemoryRegion};
pub use mem::{kseg0_to_phys, kseg1_to_phys, phys_to_kseg1, to_phys};
pub use peripheral::{
    apply_atomic_write, dispatch_polling_tick, last_code_pc, last_mem_fault, last_pc,
    record_last_code_pc, record_last_mem_fault, record_last_pc, register_polling_tick, tick_count,
    unregister_polling_tick, wrap, InMemoryBus, MemBus, NullMemBus, Peripheral, PeripheralRef,
    PollingTickFn,
};
pub use runner::{ExitCondition, RunOutcome, Runner};
