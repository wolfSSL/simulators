/* bus.rs
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

use crate::peripheral::{MemBus, PeripheralRef};
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub struct MmioRegion {
    pub base: u64,
    pub size: u64,
    pub name: &'static str,
    pub peripheral: PeripheralRef,
}

#[derive(Default)]
pub struct Bus {
    pub regions: Vec<MmioRegion>,
}

fn trace_enabled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| match std::env::var("PIC32MZ_SIM_TRACE_MMIO") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !v.is_empty() && v != "0" && v != "false" && v != "off" && v != "no"
        }
        Err(_) => false,
    })
}

impl Bus {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn map(&mut self, base: u64, size: u64, name: &'static str, p: PeripheralRef) {
        self.regions.push(MmioRegion {
            base,
            size,
            name,
            peripheral: p,
        });
    }

    pub fn dispatch_read(&self, addr: u64, size: u8) -> u32 {
        for r in &self.regions {
            if addr >= r.base && addr < r.base + r.size {
                let off = (addr - r.base) as u32;
                let value = match r.peripheral.lock() {
                    Ok(mut g) => g.read(off, size),
                    Err(_) => {
                        log::error!("peripheral {} mutex poisoned on read", r.name);
                        0
                    }
                };
                if trace_enabled() {
                    eprintln!(
                        "[mmio] R {:>8}+0x{:03x} (0x{:08x}) sz={} -> 0x{:08x}",
                        r.name, off, addr, size, value
                    );
                }
                return value;
            }
        }
        log::warn!("unmapped MMIO read at 0x{addr:08x} (size={size})");
        if trace_enabled() {
            eprintln!("[mmio] R UNMAPPED 0x{addr:08x} sz={size} -> 0x00000000");
        }
        0
    }

    pub fn dispatch_write(&self, addr: u64, size: u8, value: u32, mem: &mut dyn MemBus) {
        for r in &self.regions {
            if addr >= r.base && addr < r.base + r.size {
                let off = (addr - r.base) as u32;
                if trace_enabled() {
                    eprintln!(
                        "[mmio] W {:>8}+0x{:03x} (0x{:08x}) sz={} <- 0x{:08x}",
                        r.name, off, addr, size, value
                    );
                }
                match r.peripheral.lock() {
                    Ok(mut g) => g.write(off, size, value, mem),
                    Err(_) => log::error!("peripheral {} mutex poisoned on write", r.name),
                }
                return;
            }
        }
        log::warn!("unmapped MMIO write at 0x{addr:08x} = 0x{value:08x} (size={size})");
        if trace_enabled() {
            eprintln!(
                "[mmio] W UNMAPPED 0x{addr:08x} sz={size} <- 0x{value:08x}"
            );
        }
    }

    /// 4 KiB pages this bus occupies. Unicorn requires page-aligned
    /// MMIO mappings.
    pub fn pages(&self) -> Vec<u64> {
        let mut set: BTreeSet<u64> = BTreeSet::new();
        for r in &self.regions {
            let start = r.base & !0xFFF;
            let end = (r.base + r.size + 0xFFF) & !0xFFF;
            let mut p = start;
            while p < end {
                set.insert(p);
                p += 0x1000;
            }
        }
        set.into_iter().collect()
    }
}
