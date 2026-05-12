/* peripheral.rs
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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Callback registered in the polling-tick registry. The closure is
/// invoked from the Unicorn block hook installed at simulator startup
/// (see `Cpu::new`) on every translation-block boundary, giving the
/// peripheral a chance to scan guest memory and react. Used by the
/// Crypto Engine to drive its large-hash polling-mode flow (Unicorn's
/// MEM_WRITE hook does not fire on writes to `mem_map`'d RAM, so we
/// can't observe BD_CTRL stores directly; instead we re-scan the BD
/// chain on every TB entry, which the wolfSSL driver's tight DESC_EN
/// poll loop hits multiple times per iteration).
pub type PollingTickFn = Box<dyn FnMut(&mut dyn MemBus) + Send + 'static>;

#[derive(Default)]
struct PollingTickRegistry {
    entries: Vec<Option<PollingTickFn>>,
}

fn tick_registry() -> &'static Mutex<PollingTickRegistry> {
    static REG: OnceLock<Mutex<PollingTickRegistry>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(PollingTickRegistry::default()))
}

/// Register a polling-tick callback. Returns an index that can be
/// passed to `unregister_polling_tick` to disarm.
pub fn register_polling_tick(callback: PollingTickFn) -> usize {
    let mut reg = tick_registry().lock().unwrap();
    reg.entries.push(Some(callback));
    reg.entries.len() - 1
}

/// Disarm a previously-registered polling tick (replaces its slot
/// with `None`; index slots are positional so we don't shift).
pub fn unregister_polling_tick(idx: usize) {
    let mut reg = tick_registry().lock().unwrap();
    if let Some(slot) = reg.entries.get_mut(idx) {
        *slot = None;
    }
}

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Called from the Unicorn block hook on each TB entry.
pub fn dispatch_polling_tick(mem: &mut dyn MemBus) {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut reg) = tick_registry().lock() {
        for slot in reg.entries.iter_mut() {
            if let Some(cb) = slot.as_mut() {
                cb(mem);
            }
        }
    }
}

pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

static LAST_PC: AtomicU64 = AtomicU64::new(0);
static LAST_CODE_PC: AtomicU64 = AtomicU64::new(0);

pub fn record_last_pc(pc: u64) {
    LAST_PC.store(pc, Ordering::Relaxed);
}

pub fn last_pc() -> u64 {
    LAST_PC.load(Ordering::Relaxed)
}

pub fn record_last_code_pc(pc: u64) {
    LAST_CODE_PC.store(pc, Ordering::Relaxed);
}

pub fn last_code_pc() -> u64 {
    LAST_CODE_PC.load(Ordering::Relaxed)
}

fn last_mem_fault_cell() -> &'static Mutex<Option<String>> {
    static SLOT: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

pub fn record_last_mem_fault(desc: String) {
    if let Ok(mut slot) = last_mem_fault_cell().lock() {
        *slot = Some(desc);
    }
}

pub fn last_mem_fault() -> Option<String> {
    last_mem_fault_cell().lock().ok().and_then(|s| s.clone())
}

/// Physical-memory accessor handed to peripherals on every write so they
/// can DMA SA/BD records and source/destination buffers in or out of
/// emulator RAM. `paddr` is a PIC32 physical address (0x0000_0000 ..
/// 0x1FFF_FFFF); implementations are expected to translate to whatever
/// virtual alias the simulator has mapped RAM at (KSEG1 in our case).
/// Not `Send` - lives only inside a synchronous MMIO callback.
pub trait MemBus {
    fn read_phys(&mut self, paddr: u64, buf: &mut [u8]) -> anyhow::Result<()>;
    fn write_phys(&mut self, paddr: u64, buf: &[u8]) -> anyhow::Result<()>;
}

/// No-op MemBus, useful for unit tests that exercise a peripheral's
/// register layer without performing DMA. Reads return zeros and writes
/// are dropped.
pub struct NullMemBus;

impl MemBus for NullMemBus {
    fn read_phys(&mut self, _paddr: u64, buf: &mut [u8]) -> anyhow::Result<()> {
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(())
    }
    fn write_phys(&mut self, _paddr: u64, _buf: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}

/// In-memory MemBus backed by a sparse byte map. Used by unit tests.
#[derive(Default)]
pub struct InMemoryBus {
    bytes: std::collections::BTreeMap<u64, u8>,
}

impl InMemoryBus {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn store(&mut self, paddr: u64, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.bytes.insert(paddr + i as u64, *b);
        }
    }
    pub fn load(&self, paddr: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for i in 0..len {
            if let Some(b) = self.bytes.get(&(paddr + i as u64)) {
                out[i] = *b;
            }
        }
        out
    }
}

impl MemBus for InMemoryBus {
    fn read_phys(&mut self, paddr: u64, buf: &mut [u8]) -> anyhow::Result<()> {
        for i in 0..buf.len() {
            buf[i] = self.bytes.get(&(paddr + i as u64)).copied().unwrap_or(0);
        }
        Ok(())
    }
    fn write_phys(&mut self, paddr: u64, buf: &[u8]) -> anyhow::Result<()> {
        for (i, b) in buf.iter().enumerate() {
            self.bytes.insert(paddr + i as u64, *b);
        }
        Ok(())
    }
}

/// MMIO peripheral interface. Writes carry a `MemBus` so a peripheral
/// (like the Crypto Engine) can fetch buffer-descriptor / security-
/// association records and DMA source/destination buffers right
/// inside the store that kicked it off. PIC32 atomic SET/CLR/INV
/// register aliasing (base+4/+8/+0xC = SET/CLR/INV) is the peripheral's
/// responsibility - use `apply_atomic_write` below.
pub trait Peripheral: Send {
    fn name(&self) -> &str {
        "unnamed"
    }
    fn read(&mut self, offset: u32, size: u8) -> u32;
    fn write(&mut self, offset: u32, size: u8, value: u32, mem: &mut dyn MemBus);

    /// Optional periodic work (RNG entropy refill, CP0 Count drive).
    fn tick(&mut self, _cycles: u64) {}
}

pub type PeripheralRef = Arc<Mutex<dyn Peripheral + Send>>;

pub fn wrap<P: Peripheral + Send + 'static>(p: P) -> PeripheralRef {
    Arc::new(Mutex::new(p))
}

/// Helper that applies a PIC32 atomic-register write to an existing u32.
/// `offset_within_quad` is 0..3 word lanes (0=base, 1=SET, 2=CLR, 3=INV).
/// Returns the new register value.
pub fn apply_atomic_write(current: u32, offset_within_quad: u32, value: u32) -> u32 {
    match offset_within_quad {
        0 => value,
        1 => current | value,
        2 => current & !value,
        3 => current ^ value,
        _ => current,
    }
}
