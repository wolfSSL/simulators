/* pic32mz_ef.rs
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

use anyhow::Result;
use pic32mz_sim_core::peripheral::wrap;
use pic32mz_sim_core::{Bus, MemoryRegion};
use pic32mz_sim_peripherals::{uart::StdoutSink, CryptoEngine, Rng, Uart};

use crate::Chip;

/// PIC32MZ2048EFH144 - EF family, 2 MiB program flash, 512 KiB SRAM,
/// FPU + DSP r2 + Crypto Engine. CECON.OUT_SWAP (bit 7) is honoured;
/// the TRNG path is the wolfSSL default.
///
/// Memory map. Unicorn's MIPS core translates KSEG0 / KSEG1 virtual
/// addresses to physical via the fixed segment mapping, so we map
/// memory at physical addresses; firmware accesses through the KSEG1
/// alias just work. KSEG2 and USEG would need TLB setup which we do
/// not provide.
///
///   FLASH     phys 0x1D00_0000  2 MiB   (firmware accesses via 0xBD00_0000)
///   BOOT_FLASH phys 0x1FC0_0000 160 KiB (accessed via 0xBFC0_0000)
///   SRAM      phys 0x0000_0000  512 KiB (accessed via 0xA000_0000)
///
/// Peripheral pages: registered at their *physical* base. Unicorn's
/// MIPS core translates KSEG1 stores (0xBFxx_xxxx) to physical
/// (0x1Fxx_xxxx) before dispatching to MMIO callbacks, so the
/// firmware's pokes to 0xBF82_2000 / 0xBF88_6000 / 0xBF8E_0000 land
/// at the physical mappings below:
///   UART2 @ 0x1F82_2000 (firmware sees 0xBF82_2000)
///   RNG   @ 0x1F88_6000 (firmware sees 0xBF88_6000)
///   CE    @ 0x1F8E_0000 (firmware sees 0xBF8E_0000)
pub fn build() -> Result<Chip> {
    let memory = vec![
        MemoryRegion { base: 0x0000_0000, size: 0x0008_0000, name: "SRAM" },
        MemoryRegion { base: 0x1D00_0000, size: 0x0020_0000, name: "FLASH" },
        MemoryRegion { base: 0x1FC0_0000, size: 0x0002_8000, name: "BOOT_FLASH" },
    ];

    let mut bus = Bus::new();

    let uart2 = wrap(Uart::new("uart2", Box::new(StdoutSink)));
    bus.map(0x1F82_2000, 0x0200, "uart2", uart2);

    let rng = wrap(Rng::new());
    bus.map(0x1F88_6000, 0x0100, "rng", rng);

    let ce = wrap(CryptoEngine::new());
    bus.map(0x1F8E_0000, 0x0100, "ce", ce);

    Ok(Chip {
        name: "pic32mz2048efh144",
        memory_regions: memory,
        bus,
    })
}
