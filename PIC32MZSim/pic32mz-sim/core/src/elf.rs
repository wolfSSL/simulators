/* elf.rs
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

use anyhow::{anyhow, Context, Result};
use goblin::elf::{program_header::PT_LOAD, Elf};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct LoadSegment {
    /// Load address (LMA, ELF `p_paddr`).
    pub load_address: u64,
    /// Runtime address (VMA, ELF `p_vaddr`).
    pub runtime_address: u64,
    pub data: Vec<u8>,
    pub mem_size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub name: &'static str,
}

impl MemoryRegion {
    pub fn contains_range(&self, addr: u64, size: u64) -> bool {
        let end = match addr.checked_add(size) {
            Some(v) => v,
            None => return false,
        };
        addr >= self.base && end <= self.base + self.size
    }
}

pub struct ElfImage {
    pub entry_point: u64,
    /// Initial stack pointer. Read from the linker symbol `_stack_top`
    /// (preferred) or `__stack_top__`; PIC32 firmware does not have a
    /// Cortex-M-style vector table to lift SP from. If neither symbol
    /// is present, falls back to 0 and the firmware's startup code
    /// must set `$sp` itself before touching the stack.
    pub initial_sp: u64,
    pub segments: Vec<LoadSegment>,
    pub symbols: HashMap<String, u64>,
}

impl ElfImage {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read ELF file: {}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let elf = Elf::parse(bytes).map_err(|e| anyhow!("failed to parse ELF: {e}"))?;

        let mut segments = Vec::new();
        for ph in &elf.program_headers {
            if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
                continue;
            }
            let start = ph.p_offset as usize;
            let end = start + ph.p_filesz as usize;
            if end > bytes.len() {
                anyhow::bail!("PT_LOAD segment extends past file end");
            }
            segments.push(LoadSegment {
                load_address: ph.p_paddr,
                runtime_address: ph.p_vaddr,
                mem_size: ph.p_memsz,
                data: bytes[start..end].to_vec(),
            });
        }

        let mut symbols: HashMap<String, u64> = HashMap::new();
        for sym in elf.syms.iter() {
            let name: &str = match elf.strtab.get_at(sym.st_name) {
                Some(n) => n,
                None => continue,
            };
            if !name.is_empty() {
                symbols.insert(name.to_string(), sym.st_value);
            }
        }

        let initial_sp = symbols
            .get("_stack_top")
            .or_else(|| symbols.get("__stack_top__"))
            .or_else(|| symbols.get("_stack"))
            .copied()
            .unwrap_or(0);

        Ok(Self {
            entry_point: elf.entry,
            initial_sp,
            segments,
            symbols,
        })
    }

    pub fn loadable_segments(&self) -> &[LoadSegment] {
        &self.segments
    }

    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }
}
