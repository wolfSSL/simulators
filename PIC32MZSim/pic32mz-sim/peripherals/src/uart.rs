/* uart.rs
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

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use pic32mz_sim_core::{MemBus, Peripheral};

pub trait UartSink: Send {
    fn write_byte(&mut self, b: u8);
    fn flush(&mut self) {}
}

pub struct StdoutSink;

impl UartSink for StdoutSink {
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

impl UartSink for CapturingSink {
    fn write_byte(&mut self, b: u8) {
        if let Ok(mut g) = self.buf.lock() {
            g.push(b);
        }
    }
}

/// PIC32MZ UART register layout (a single instance, e.g. U2 at
/// 0xBF82_2000). Each register occupies a 16-byte slot to make room
/// for the atomic SET/CLR/INV aliases at +4/+8/+0xC.
///
///   0x000 UMODE   0x010 USTA   0x020 UBRG
///   0x030 UTXREG  0x040 URXREG
///
/// Writes to UTXREG push one byte to the sink; reads from USTA report
/// the FIFO as always empty (TRMT=1, UTXBF=0) so firmware never blocks
/// waiting for TX FIFO drain.
pub struct Uart {
    name: &'static str,
    sink: Box<dyn UartSink>,
    umode: u32,
    usta: u32,
    ubrg: u32,
}

impl Uart {
    pub fn new(name: &'static str, sink: Box<dyn UartSink>) -> Self {
        Self {
            name,
            sink,
            umode: 0,
            usta: 0,
            ubrg: 0,
        }
    }
}

const UMODE_OFF: u32 = 0x000;
const USTA_OFF: u32 = 0x010;
const UBRG_OFF: u32 = 0x020;
const UTXREG_OFF: u32 = 0x030;
const URXREG_OFF: u32 = 0x040;

fn atomic_op(current: u32, lane: u32, value: u32) -> u32 {
    match lane {
        0 => value,
        1 => current | value,
        2 => current & !value,
        3 => current ^ value,
        _ => current,
    }
}

fn split_atomic(offset: u32, base: u32) -> Option<u32> {
    let delta = offset.wrapping_sub(base);
    if delta < 16 {
        Some(delta >> 2)
    } else {
        None
    }
}

impl Peripheral for Uart {
    fn name(&self) -> &str {
        self.name
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        if let Some(lane) = split_atomic(offset, UMODE_OFF) {
            if lane == 0 {
                return self.umode;
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, USTA_OFF) {
            if lane == 0 {
                // USTA: TRMT=1 (bit 8, transmit shift empty), UTXBF=0
                // (bit 9, tx buffer not full), URXDA=0 (bit 0, rx data
                // available - we have no RX). Other bits remain as
                // last-written.
                return (self.usta & !((1 << 8) | (1 << 9) | (1 << 0))) | (1 << 8);
            }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, UBRG_OFF) {
            if lane == 0 {
                return self.ubrg;
            }
            return 0;
        }
        if let Some(_) = split_atomic(offset, URXREG_OFF) {
            return 0;
        }
        0
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32, _mem: &mut dyn MemBus) {
        if let Some(lane) = split_atomic(offset, UMODE_OFF) {
            self.umode = atomic_op(self.umode, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, USTA_OFF) {
            self.usta = atomic_op(self.usta, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, UBRG_OFF) {
            self.ubrg = atomic_op(self.ubrg, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, UTXREG_OFF) {
            if lane == 0 {
                self.sink.write_byte((value & 0xFF) as u8);
            }
            return;
        }
    }
}
