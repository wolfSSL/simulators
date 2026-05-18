/* pic32mz_ec.rs
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

/// PIC32MZ2048ECH144 - EC family, 2 MiB program flash, 512 KiB SRAM,
/// no FPU, Crypto Engine present but CECON.OUT_SWAP is ignored in
/// hardware (`PIC32_NO_OUT_SWAP` in the wolfSSL port). The wolfSSL
/// random.c also skips the TRNG seed step on EC and falls back to a
/// CP0 Count seed.
///
/// Memory map and peripheral pages are identical to EF (the CE block
/// has the same SFR layout); the only behavioural difference is the
/// `no_out_swap` flag on the CE peripheral.
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

    let ce = wrap(CryptoEngine::for_ec());
    bus.map(0x1F8E_0000, 0x0100, "ce", ce);

    Ok(Chip {
        name: "pic32mz2048ech144",
        memory_regions: memory,
        bus,
    })
}
