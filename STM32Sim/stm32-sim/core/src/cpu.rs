/* cpu.rs
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

use anyhow::{anyhow, Result};
use std::sync::Arc;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{ArmCpuModel, RegisterARM, Unicorn};

use crate::bus::Bus;
use crate::elf::{ElfImage, MemoryRegion};

#[derive(Debug, Clone, Copy)]
pub enum CpuStop {
    /// emu_start returned without error.
    Halted,
    /// emu_start returned an error (fault, bad memory, etc.).
    Fault,
}

/// CPU family selector. Determines the Unicorn `Mode` flags and whether
/// the runtime treats addresses as Thumb (M-class) or ARM (A-class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuKind {
    /// Cortex-M0/M3/M4/M7/M33 - Thumb-2 only, M-profile vector table.
    CortexM,
    /// Cortex-A series (A7, A15, ...) - ARMv7-A with MMU support.
    CortexA,
}

pub struct Cpu {
    uc: Unicorn<'static, ()>,
    kind: CpuKind,
}

impl Cpu {
    pub fn new(memory: &[MemoryRegion]) -> Result<Self> {
        Self::new_with_kind(memory, CpuKind::CortexM)
    }

    pub fn new_with_kind(memory: &[MemoryRegion], kind: CpuKind) -> Result<Self> {
        let mode = match kind {
            CpuKind::CortexM => Mode::THUMB | Mode::MCLASS,
            // ARMv7-A starts in ARM (not Thumb). No MCLASS flag - that
            // is the bit that switches Unicorn into M-profile exception
            // semantics. Without it we get an A-class CPU with MMU,
            // VFP/NEON, and SVC-mode boot.
            CpuKind::CortexA => Mode::ARM,
        };
        let mut uc = Unicorn::new(Arch::ARM, mode)
            .map_err(|e| anyhow!("Unicorn::new failed: {e:?}"))?;
        if let CpuKind::CortexA = kind {
            // The default A-class CPU in Unicorn does not advertise an
            // MMU or VFPv4/NEON. Pin to Cortex-A7 so MP135 firmware can
            // enable its translation tables and use VFP/NEON-compiled
            // wolfSSL code.
            uc.ctl_set_cpu_model(ArmCpuModel::CORTEX_A7 as i32)
                .map_err(|e| anyhow!("ctl_set_cpu_model(CORTEX_A7) failed: {e:?}"))?;
        }
        for region in memory {
            uc.mem_map(region.base, region.size, Prot::ALL)
                .map_err(|e| {
                    anyhow!(
                        "mem_map {} @ 0x{:08x} ({} bytes) failed: {:?}",
                        region.name,
                        region.base,
                        region.size,
                        e
                    )
                })?;
        }
        Ok(Self { uc, kind })
    }

    /// Install a Bus: register one Unicorn MMIO callback per 4 KiB page
    /// the bus covers. The closure dispatches into the bus, which routes
    /// to the right peripheral.
    pub fn install_bus(&mut self, bus: Bus) -> Result<()> {
        let arc = Arc::new(bus);
        for page in arc.pages() {
            let bus_r = arc.clone();
            let bus_w = arc.clone();
            let base = page;
            self.uc
                .mmio_map(
                    base,
                    0x1000u64,
                    Some(move |_uc: &mut Unicorn<()>, offset: u64, size: usize| -> u64 {
                        bus_r.dispatch_read(base + offset, size as u8) as u64
                    }),
                    Some(
                        move |_uc: &mut Unicorn<()>, offset: u64, size: usize, value: u64| {
                            bus_w.dispatch_write(base + offset, size as u8, value as u32);
                        },
                    ),
                )
                .map_err(|e| anyhow!("mmio_map page 0x{:08x} failed: {:?}", page, e))?;
        }
        Ok(())
    }

    pub fn load_elf(&mut self, image: &ElfImage) -> Result<()> {
        for seg in image.loadable_segments() {
            // Write initial bytes at the LMA (load_address). For
            // bare-metal Cortex-M ELFs this is the flash location;
            // the firmware's startup code copies VMA-targeted
            // sections (e.g. `.data`) into SRAM at boot.
            self.uc
                .mem_write(seg.load_address, &seg.data)
                .map_err(|e| {
                    anyhow!(
                        "mem_write segment 0x{:08x} ({} bytes): {:?}",
                        seg.load_address,
                        seg.data.len(),
                        e
                    )
                })?;
        }
        // The Thumb bit (LSB=1) marks Cortex-M ELF entry points; on
        // A-class the bit is already 0. Stripping it is safe in both
        // cases. The SP slot for A-class is also unused: A-class
        // firmware sets its own stacks from its startup code (one per
        // exception mode), but writing a reasonable SP is harmless if
        // the ELF has one.
        let pc = image.entry_point & !1;
        self.uc
            .reg_write(RegisterARM::SP, image.initial_sp)
            .map_err(|e| anyhow!("reg_write SP: {e:?}"))?;
        self.uc
            .reg_write(RegisterARM::PC, pc)
            .map_err(|e| anyhow!("reg_write PC: {e:?}"))?;
        Ok(())
    }

    /// Run up to `max_instructions` instructions, then return.
    pub fn run(&mut self, max_instructions: u64) -> Result<CpuStop> {
        let pc = self
            .uc
            .reg_read(RegisterARM::PC)
            .map_err(|e| anyhow!("reg_read PC: {e:?}"))?;
        // emu_start expects (begin | 1) when the next instruction is a
        // Thumb instruction. Cortex-M is always Thumb. Cortex-A toggles
        // between ARM and Thumb at runtime, so probe CPSR.T (bit 5) for
        // each slice - resuming with the wrong bit corrupts the decode
        // and Unicorn reports it as INSN_INVALID at the resume address.
        let begin = match self.kind {
            CpuKind::CortexM => pc | 1,
            CpuKind::CortexA => {
                let cpsr = self
                    .uc
                    .reg_read(RegisterARM::CPSR)
                    .map_err(|e| anyhow!("reg_read CPSR: {e:?}"))?;
                if cpsr & (1 << 5) != 0 {
                    pc | 1
                } else {
                    pc & !1
                }
            }
        };
        match self
            .uc
            .emu_start(begin, 0, 0, max_instructions as usize)
        {
            Ok(()) => Ok(CpuStop::Halted),
            Err(e) => {
                log::error!("emu_start error at PC=0x{pc:08x}: {e:?}");
                Ok(CpuStop::Fault)
            }
        }
    }

    pub fn read_u32(&mut self, addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.uc
            .mem_read(addr, &mut buf)
            .map_err(|e| anyhow!("mem_read u32 @ 0x{addr:08x}: {e:?}"))?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_pc(&self) -> Result<u64> {
        self.uc
            .reg_read(RegisterARM::PC)
            .map_err(|e| anyhow!("reg_read PC: {e:?}"))
    }

    pub fn read_bytes(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.uc
            .mem_read(addr, &mut buf)
            .map_err(|e| anyhow!("mem_read {len}B @ 0x{addr:08x}: {e:?}"))?;
        Ok(buf)
    }

    pub fn ensure_segments_fit(&self, image: &ElfImage, regions: &[MemoryRegion]) -> Result<()> {
        for seg in image.loadable_segments() {
            // The LMA (load_address) holds the initial bytes (typically
            // flash); the VMA (runtime_address) is where the firmware
            // expects to access the segment at runtime (typically SRAM
            // for `.data`). Both must be inside a configured memory
            // region or the firmware will fault.
            for (label, addr, size) in [
                ("LMA", seg.load_address, seg.data.len() as u64),
                ("VMA", seg.runtime_address, seg.mem_size),
            ] {
                if size == 0 {
                    continue;
                }
                if !regions.iter().any(|r| r.contains_range(addr, size)) {
                    anyhow::bail!(
                        "ELF segment {label} 0x{addr:08x} (size 0x{size:x}) not covered by any chip memory region"
                    );
                }
            }
        }
        Ok(())
    }
}
