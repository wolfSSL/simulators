/* transport.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// Mock I2C transport implementing embedded_hal 0.2 blocking I2C traits.
/// Routes I2C read/write calls through the T=1 responder to the APDU engine.

use std::collections::VecDeque;

use crate::object_store::ObjectStore;
use crate::t1::T1Responder;

/// The SE050 simulator. Implements `embedded_hal::blocking::i2c::Read` and `Write`
/// so it can be used directly with the nxp-se050 driver's `T1overI2C`.
pub struct Se050Simulator {
    t1: T1Responder,
    store: ObjectStore,
    /// Response chunks queued for I2C reads.
    /// Each chunk is either a 3-byte header or a payload+CRC block.
    read_chunks: VecDeque<Vec<u8>>,
}

#[derive(Debug)]
pub enum SimError {
    NoData,
    BufferTooSmall,
    ProtocolError,
}

impl Se050Simulator {
    /// Create a new simulator with in-memory object store.
    pub fn new() -> Self {
        Self {
            t1: T1Responder::new(0x5A),
            store: ObjectStore::new(),
            read_chunks: VecDeque::new(),
        }
    }

    /// Create a new simulator with persistent object store.
    pub fn with_persistence(path: std::path::PathBuf) -> Self {
        Self {
            t1: T1Responder::new(0x5A),
            store: ObjectStore::with_persistence(path),
            read_chunks: VecDeque::new(),
        }
    }

    /// Get a reference to the object store.
    pub fn store(&self) -> &ObjectStore {
        &self.store
    }

    /// Get a mutable reference to the object store.
    pub fn store_mut(&mut self) -> &mut ObjectStore {
        &mut self.store
    }
}

impl Default for Se050Simulator {
    fn default() -> Self {
        Self::new()
    }
}

impl embedded_hal::blocking::i2c::Write for Se050Simulator {
    type Error = SimError;

    fn write(&mut self, _addr: u8, data: &[u8]) -> Result<(), Self::Error> {
        // Process the incoming T=1 frame through the responder
        let response_chunks = self.t1.process_frame(data, &mut self.store);

        // Queue response chunks for subsequent reads
        for chunk in response_chunks {
            self.read_chunks.push_back(chunk);
        }

        Ok(())
    }
}

impl embedded_hal::blocking::i2c::Read for Se050Simulator {
    type Error = SimError;

    fn read(&mut self, _addr: u8, buf: &mut [u8]) -> Result<(), Self::Error> {
        let chunk = self.read_chunks.pop_front().ok_or(SimError::NoData)?;

        if chunk.len() > buf.len() {
            // If chunk is larger than buffer, copy what fits
            // This shouldn't happen in normal operation since the driver
            // requests exactly the right number of bytes
            buf.copy_from_slice(&chunk[..buf.len()]);
        } else {
            buf[..chunk.len()].copy_from_slice(&chunk);
        }

        Ok(())
    }
}
