/* peripheral.rs
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

use std::sync::{Arc, Mutex};

/// MMIO peripheral interface. All accesses are u32-wide on the wire to
/// Unicorn; `size` reflects the original ARM ldr/strh/strb width so a
/// peripheral can refuse byte writes to a register that requires word
/// access (the STM32 reference manual is strict about this for some
/// peripherals).
pub trait Peripheral: Send {
    fn name(&self) -> &str {
        "unnamed"
    }
    fn read(&mut self, offset: u32, size: u8) -> u32;
    fn write(&mut self, offset: u32, size: u8, value: u32);

    /// Optional periodic work (e.g. RNG entropy refill, DMA timers).
    /// Called by the runner between instruction slices.
    fn tick(&mut self, _cycles: u64) {}
}

pub type PeripheralRef = Arc<Mutex<dyn Peripheral + Send>>;

pub fn wrap<P: Peripheral + Send + 'static>(p: P) -> PeripheralRef {
    Arc::new(Mutex::new(p))
}
