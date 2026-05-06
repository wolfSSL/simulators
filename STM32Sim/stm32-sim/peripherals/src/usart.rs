/* usart.rs
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

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use stm32_sim_core::peripheral::Peripheral;

pub trait UsartSink: Send {
    fn write_byte(&mut self, b: u8);
    fn flush(&mut self) {}
}

pub struct StdoutSink;

impl UsartSink for StdoutSink {
    fn write_byte(&mut self, b: u8) {
        if b == b'\r' {
            return;
        }
        let stdout = io::stdout();
        let mut h = stdout.lock();
        let _ = h.write_all(&[b]);
        if b == b'\n' {
            let _ = h.flush();
        }
    }
}

#[derive(Default, Clone)]
pub struct CapturingSink {
    pub buf: Arc<Mutex<Vec<u8>>>,
}

impl CapturingSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn snapshot(&self) -> Vec<u8> {
        self.buf.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl UsartSink for CapturingSink {
    fn write_byte(&mut self, b: u8) {
        if let Ok(mut g) = self.buf.lock() {
            g.push(b);
        }
    }
}

/// STM32 H7/U5 USART register layout (the F4/F7 layout differs and is
/// not modelled here yet). Offsets:
///   0x00 CR1   0x04 CR2   0x08 CR3   0x0C BRR
///   0x1C ISR   0x20 ICR   0x24 RDR   0x28 TDR
pub struct Usart {
    name: &'static str,
    sink: Box<dyn UsartSink>,
    cr1: u32,
    cr2: u32,
    cr3: u32,
    brr: u32,
}

impl Usart {
    pub fn new(name: &'static str, sink: Box<dyn UsartSink>) -> Self {
        Self {
            name,
            sink,
            cr1: 0,
            cr2: 0,
            cr3: 0,
            brr: 0,
        }
    }
}

impl Peripheral for Usart {
    fn name(&self) -> &str {
        self.name
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match offset {
            0x00 => self.cr1,
            0x04 => self.cr2,
            0x08 => self.cr3,
            0x0C => self.brr,
            // ISR: TXE_TXFNF (bit 7) and TC (bit 6) always set so firmware
            // never blocks waiting for the TX FIFO to drain.
            0x1C => 0x0000_00C0,
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match offset {
            0x00 => self.cr1 = value,
            0x04 => self.cr2 = value,
            0x08 => self.cr3 = value,
            0x0C => self.brr = value,
            0x20 => {} // ICR write-1-to-clear, no-op for stub
            0x28 => self.sink.write_byte((value & 0xFF) as u8), // TDR
            _ => {}
        }
    }
}
