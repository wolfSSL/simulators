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

/// USART register layout generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsartLayout {
    /// H7/U5/MP13 (and F7/L4) layout:
    ///   0x00 CR1   0x04 CR2   0x08 CR3   0x0C BRR
    ///   0x1C ISR   0x20 ICR   0x24 RDR   0x28 TDR
    Modern,
    /// F1/F2/F4 layout:
    ///   0x00 SR    0x04 DR    0x08 BRR   0x0C CR1
    ///   0x10 CR2   0x14 CR3   0x18 GTPR
    Legacy,
}

/// STM32 USART, transmit side only. TXE and TC always read as set so
/// firmware never blocks waiting for the transmitter.
pub struct Usart {
    name: &'static str,
    layout: UsartLayout,
    sink: Box<dyn UsartSink>,
    cr1: u32,
    cr2: u32,
    cr3: u32,
    brr: u32,
    gtpr: u32,
}

/// ISR / SR bits 7 (TXE) and 6 (TC); the same positions in both layouts.
const TX_READY: u32 = 0x0000_00C0;

impl Usart {
    /// H7/U5-style USART.
    pub fn new(name: &'static str, sink: Box<dyn UsartSink>) -> Self {
        Self::with_layout(name, UsartLayout::Modern, sink)
    }

    /// F1/F2/F4-style USART.
    pub fn new_legacy(name: &'static str, sink: Box<dyn UsartSink>) -> Self {
        Self::with_layout(name, UsartLayout::Legacy, sink)
    }

    pub fn with_layout(name: &'static str, layout: UsartLayout, sink: Box<dyn UsartSink>) -> Self {
        Self {
            name,
            layout,
            sink,
            cr1: 0,
            cr2: 0,
            cr3: 0,
            brr: 0,
            gtpr: 0,
        }
    }
}

impl Peripheral for Usart {
    fn name(&self) -> &str {
        self.name
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        match (self.layout, offset) {
            (UsartLayout::Modern, 0x00) => self.cr1,
            (UsartLayout::Modern, 0x04) => self.cr2,
            (UsartLayout::Modern, 0x08) => self.cr3,
            (UsartLayout::Modern, 0x0C) => self.brr,
            (UsartLayout::Modern, 0x1C) => TX_READY, // ISR
            (UsartLayout::Legacy, 0x00) => TX_READY, // SR
            (UsartLayout::Legacy, 0x08) => self.brr,
            (UsartLayout::Legacy, 0x0C) => self.cr1,
            (UsartLayout::Legacy, 0x10) => self.cr2,
            (UsartLayout::Legacy, 0x14) => self.cr3,
            (UsartLayout::Legacy, 0x18) => self.gtpr,
            _ => 0,
        }
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32) {
        match (self.layout, offset) {
            (UsartLayout::Modern, 0x00) => self.cr1 = value,
            (UsartLayout::Modern, 0x04) => self.cr2 = value,
            (UsartLayout::Modern, 0x08) => self.cr3 = value,
            (UsartLayout::Modern, 0x0C) => self.brr = value,
            (UsartLayout::Modern, 0x28) => self.sink.write_byte((value & 0xFF) as u8), // TDR
            (UsartLayout::Legacy, 0x04) => self.sink.write_byte((value & 0xFF) as u8), // DR
            (UsartLayout::Legacy, 0x08) => self.brr = value,
            (UsartLayout::Legacy, 0x0C) => self.cr1 = value,
            (UsartLayout::Legacy, 0x10) => self.cr2 = value,
            (UsartLayout::Legacy, 0x14) => self.cr3 = value,
            (UsartLayout::Legacy, 0x18) => self.gtpr = value,
            _ => {} // ICR (modern) / SR clears (legacy): no-op for the stub
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_layout_transmits_on_dr() {
        let sink = CapturingSink::new();
        let mut u = Usart::new_legacy("usart2", Box::new(sink.clone()));
        u.write(0x0C, 4, 0x200C); // CR1: UE | TE | RE
        assert_eq!(u.read(0x0C, 4), 0x200C);
        assert_eq!(u.read(0x00, 4) & TX_READY, TX_READY);
        for b in b"ok" {
            u.write(0x04, 4, *b as u32);
        }
        u.write(0x28, 4, b'x' as u32); // TDR offset means nothing here
        assert_eq!(sink.snapshot(), b"ok");
    }

    #[test]
    fn modern_layout_transmits_on_tdr() {
        let sink = CapturingSink::new();
        let mut u = Usart::new("usart3", Box::new(sink.clone()));
        u.write(0x04, 4, b'x' as u32); // CR2, not data
        u.write(0x28, 4, b'h' as u32);
        assert_eq!(u.read(0x1C, 4), TX_READY);
        assert_eq!(sink.snapshot(), b"h");
    }
}
