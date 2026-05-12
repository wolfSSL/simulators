/* cpu.rs
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

use anyhow::{anyhow, Result};
use std::sync::Arc;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterMIPS, Unicorn};

use crate::bus::Bus;
use crate::elf::{ElfImage, MemoryRegion};
use crate::mem::to_phys;
use crate::peripheral::MemBus;

/// MemBus adapter backed by a live Unicorn instance. Used inside the
/// MMIO write callback so peripherals can DMA from emulator RAM during
/// the store instruction that kicked them off. Addresses are PIC32
/// physical (paddr); this struct rewrites them to the KSEG1 alias the
/// chip configuration mapped RAM at.
struct UcMemBus<'a, 'b> {
    uc: &'a mut Unicorn<'b, ()>,
}

impl<'a, 'b> MemBus for UcMemBus<'a, 'b> {
    fn read_phys(&mut self, paddr: u64, buf: &mut [u8]) -> anyhow::Result<()> {
        // Unicorn-side RAM is mapped at physical addresses; KSEG
        // translation happens during instruction fetch and loads /
        // stores. For DMA we already have a physical address, so
        // read directly.
        let pa = to_phys(paddr);
        self.uc
            .mem_read(pa, buf)
            .map_err(|e| anyhow!("uc mem_read paddr=0x{paddr:08x} ({}B): {e:?}", buf.len()))
    }
    fn write_phys(&mut self, paddr: u64, buf: &[u8]) -> anyhow::Result<()> {
        let pa = to_phys(paddr);
        self.uc
            .mem_write(pa, buf)
            .map_err(|e| anyhow!("uc mem_write paddr=0x{paddr:08x} ({}B): {e:?}", buf.len()))
    }

}

#[derive(Debug, Clone, Copy)]
pub enum CpuStop {
    /// emu_start returned without error.
    Halted,
    /// emu_start returned an error (fault, bad memory, etc.).
    Fault,
}

pub struct Cpu {
    uc: Unicorn<'static, ()>,
}

impl Cpu {
    pub fn new(memory: &[MemoryRegion]) -> Result<Self> {
        let mut uc = Unicorn::new(Arch::MIPS, Mode::MIPS32 | Mode::LITTLE_ENDIAN)
            .map_err(|e| anyhow!("Unicorn::new failed: {e:?}"))?;
        for region in memory {
            log::info!(
                "mem_map {} @ 0x{:08x} size 0x{:x}",
                region.name,
                region.base,
                region.size
            );
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

        // Pre-install a block hook that drives the global polling-mode
        // dispatcher on every translation-block boundary. Unicorn's
        // `MEM_WRITE` hook does NOT fire on writes to `mem_map`'d
        // memory in 2.1.5 (only on MMIO or invalid accesses), so we
        // can't observe BD_CTRL stores directly. Instead, on every
        // TB entry the CE peripheral re-scans the BD chain for any
        // BD with DESC_EN=1 and processes it. Block hooks fire often
        // enough (the wolfSSL DESC_EN poll loop is one short TB) that
        // the firmware never times out waiting.
        //
        // Installing BEFORE Unicorn translates any code is important
        // so the hook applies to all subsequent TBs.
        uc.add_block_hook(0, u64::MAX, |uc: &mut Unicorn<()>, pc: u64, _size: u32| {
            crate::peripheral::record_last_pc(pc);
            let mut mem = UcMemBus { uc };
            crate::peripheral::dispatch_polling_tick(&mut mem);
        })
        .map_err(|e| anyhow!("polling-tick block hook install failed: {e:?}"))?;

        // Mem-invalid hook: capture the address/size/type of any access
        // that Unicorn refuses (unmapped, permission). Unicorn 2.1.5's
        // Rust bindings do not expose the dedicated UC_HOOK_MEM_*_UNALIGNED
        // hook types, so we also track the last *successful* memory
        // access below; on a MIPS unaligned fault the failing address
        // will be the next access attempt after the last tracked one.
        uc.add_mem_hook(
            unicorn_engine::unicorn_const::HookType::MEM_INVALID,
            0,
            u64::MAX,
            |_uc: &mut Unicorn<()>, mem_type, address, size, _value| {
                crate::peripheral::record_last_mem_fault(format!(
                    "{:?} addr=0x{:08x} size={}",
                    mem_type, address, size
                ));
                false
            },
        )
        .map_err(|e| anyhow!("mem-invalid hook install failed: {e:?}"))?;
        // Code hook: track the most recently *executed* PC so on a fault
        // we know precisely which instruction tripped Unicorn.
        uc.add_code_hook(0, u64::MAX, |_uc: &mut Unicorn<()>, pc: u64, _size: u32| {
            crate::peripheral::record_last_code_pc(pc);
        })
        .map_err(|e| anyhow!("code hook install failed: {e:?}"))?;

        Ok(Self { uc })
    }

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
                        move |uc: &mut Unicorn<()>, offset: u64, size: usize, value: u64| {
                            let mut mem = UcMemBus { uc };
                            bus_w.dispatch_write(base + offset, size as u8, value as u32, &mut mem);
                        },
                    ),
                )
                .map_err(|e| anyhow!("mmio_map page 0x{:08x} failed: {:?}", page, e))?;
        }
        Ok(())
    }

    pub fn load_elf(&mut self, image: &ElfImage) -> Result<()> {
        // The simulator maps RAM/flash at *physical* addresses (low
        // half). The ELF segment LMAs are virtual (typically KSEG1
        // 0xBD00_0000 for .text + .data initialisers). Strip the
        // segment selector before writing so the bytes land where
        // KSEG translation will fetch them.
        for seg in image.loadable_segments() {
            let pa = to_phys(seg.load_address);
            self.uc
                .mem_write(pa, &seg.data)
                .map_err(|e| {
                    anyhow!(
                        "mem_write segment va=0x{:08x} pa=0x{:08x} ({} bytes): {:?}",
                        seg.load_address,
                        pa,
                        seg.data.len(),
                        e
                    )
                })?;
        }

        if image.initial_sp != 0 {
            self.uc
                .reg_write(RegisterMIPS::SP, image.initial_sp)
                .map_err(|e| anyhow!("reg_write SP: {e:?}"))?;
        }
        self.uc
            .reg_write(RegisterMIPS::PC, image.entry_point)
            .map_err(|e| anyhow!("reg_write PC: {e:?}"))?;
        Ok(())
    }

    /// Run up to `max_instructions` instructions, then return.
    pub fn run(&mut self, max_instructions: u64) -> Result<CpuStop> {
        let pc = self
            .uc
            .reg_read(RegisterMIPS::PC)
            .map_err(|e| anyhow!("reg_read PC: {e:?}"))?;
        log::debug!("emu_start at pc=0x{pc:08x} count={max_instructions}");
        match self.uc.emu_start(pc, 0, 0, max_instructions as usize) {
            Ok(()) => Ok(CpuStop::Halted),
            Err(e) => {
                let sp = self.uc.reg_read(RegisterMIPS::SP).unwrap_or(0);
                let ra = self.uc.reg_read(RegisterMIPS::RA).unwrap_or(0);
                let s0 = self.uc.reg_read(RegisterMIPS::S0).unwrap_or(0);
                let s1 = self.uc.reg_read(RegisterMIPS::S1).unwrap_or(0);
                let s2 = self.uc.reg_read(RegisterMIPS::S2).unwrap_or(0);
                let s3 = self.uc.reg_read(RegisterMIPS::S3).unwrap_or(0);
                let a0 = self.uc.reg_read(RegisterMIPS::A0).unwrap_or(0);
                let a1 = self.uc.reg_read(RegisterMIPS::A1).unwrap_or(0);
                let v0 = self.uc.reg_read(RegisterMIPS::V0).unwrap_or(0);
                let v1 = self.uc.reg_read(RegisterMIPS::V1).unwrap_or(0);
                log::error!(
                    "emu_start error at PC=0x{pc:08x}: {e:?}\n  sp=0x{sp:08x} ra=0x{ra:08x}\n  s0=0x{s0:08x} s1=0x{s1:08x} s2=0x{s2:08x} s3=0x{s3:08x}\n  a0=0x{a0:08x} a1=0x{a1:08x} v0=0x{v0:08x} v1=0x{v1:08x}"
                );
                Ok(CpuStop::Fault)
            }
        }
    }

    pub fn read_u32(&mut self, addr: u64) -> Result<u32> {
        let pa = to_phys(addr);
        let mut buf = [0u8; 4];
        self.uc
            .mem_read(pa, &mut buf)
            .map_err(|e| anyhow!("mem_read u32 va=0x{addr:08x} pa=0x{pa:08x}: {e:?}"))?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_pc(&self) -> Result<u64> {
        self.uc
            .reg_read(RegisterMIPS::PC)
            .map_err(|e| anyhow!("reg_read PC: {e:?}"))
    }

    pub fn read_bytes(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.uc
            .mem_read(addr, &mut buf)
            .map_err(|e| anyhow!("mem_read {len}B @ 0x{addr:08x}: {e:?}"))?;
        Ok(buf)
    }

    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.uc
            .mem_write(addr, data)
            .map_err(|e| anyhow!("mem_write {}B @ 0x{addr:08x}: {e:?}", data.len()))
    }

    pub fn ensure_segments_fit(&self, image: &ElfImage, regions: &[MemoryRegion]) -> Result<()> {
        for seg in image.loadable_segments() {
            for (label, va, size) in [
                ("LMA", seg.load_address, seg.data.len() as u64),
                ("VMA", seg.runtime_address, seg.mem_size),
            ] {
                if size == 0 {
                    continue;
                }
                let pa = to_phys(va);
                if !regions.iter().any(|r| r.contains_range(pa, size)) {
                    anyhow::bail!(
                        "ELF segment {label} va=0x{va:08x} pa=0x{pa:08x} (size 0x{size:x}) not covered by any chip memory region"
                    );
                }
            }
        }
        Ok(())
    }
}
