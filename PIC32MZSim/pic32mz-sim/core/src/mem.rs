/* mem.rs
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

//! MIPS32 segment helpers for PIC32MZ. The classic fixed-mapping MMU has
//! four segments visible to user/kernel software:
//!
//!   USEG  0x0000_0000 - 0x7FFF_FFFF  (TLB-mapped, unused on bare metal)
//!   KSEG0 0x8000_0000 - 0x9FFF_FFFF  cached, paddr = vaddr & 0x1FFF_FFFF
//!   KSEG1 0xA000_0000 - 0xBFFF_FFFF  uncached, paddr = vaddr & 0x1FFF_FFFF
//!   KSEG2 0xC000_0000 - 0xFFFF_FFFF  (TLB-mapped, unused on bare metal)
//!
//! The wolfSSL PIC32 port pokes peripherals through KSEG1 (uncached) and
//! supplies physical addresses to the Crypto Engine via `KVA_TO_PA()`.
//! These helpers convert between the segments without doing real TLB
//! lookups.

pub const KSEG0_BASE: u64 = 0x8000_0000;
pub const KSEG1_BASE: u64 = 0xA000_0000;
pub const SEG_MASK: u64 = 0x1FFF_FFFF;

/// Convert a KSEG0 virtual address to its physical address. Caller must
/// pass an address inside `0x8000_0000 .. 0xA000_0000`.
pub fn kseg0_to_phys(va: u64) -> u64 {
    va & SEG_MASK
}

/// Convert a KSEG1 virtual address to its physical address. Caller must
/// pass an address inside `0xA000_0000 .. 0xC000_0000`.
pub fn kseg1_to_phys(va: u64) -> u64 {
    va & SEG_MASK
}

/// Convert a physical address into its KSEG1 (uncached) alias.
pub fn phys_to_kseg1(pa: u64) -> u64 {
    KSEG1_BASE | (pa & SEG_MASK)
}

/// Strip any KSEG0 / KSEG1 segment selector off `va`, returning the
/// underlying physical address. USEG / KSEG2 / KSEG3 addresses are
/// returned unchanged (they require TLB walks we do not model). Used
/// by the ELF loader and the runner symbol-poll path so the firmware
/// can name memory through any segment alias and the simulator does
/// the right thing.
pub fn to_phys(va: u64) -> u64 {
    let high = (va >> 29) & 0x7;
    match high {
        // KSEG0 (100xxx) and KSEG1 (101xxx): both map to phys = va & 0x1FFF_FFFF.
        4 | 5 => va & SEG_MASK,
        // USEG, KSEG2, KSEG3: not modelled, return as-is so an out-of-range
        // address still fails the ELF-fits-memory-region check explicitly.
        _ => va,
    }
}
