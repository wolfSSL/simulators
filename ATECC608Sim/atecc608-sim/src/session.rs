/* session.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of ATECC608Sim.
 *
 * ATECC608Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * ATECC608Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// Per-TCP-connection volatile state.
///
/// On a real ATECC608A this lives in on-chip SRAM. The datasheet wipes it
/// on sleep (0x01); idle (0x02) only lowers power and the RAM survives.
/// We mirror that: `volatile_reset` is called by the TCP server when it
/// sees a sleep byte, and it's a no-op for idle and wake. cryptoauthlib's
/// multi-step SHA and Nonce+Sign flows interleave idle between the
/// sub-commands, so preserving TempKey / SHA state across idle is
/// load-bearing.
use sha2::{Digest, Sha256};

/// Which source populated TempKey. Sign/Verify pick different paths based on
/// this so we track it explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempKeySource {
    /// Loaded by a Nonce command in pass-through mode (mode=0x03). The 32
    /// bytes are the caller-supplied message directly. This is the path
    /// wolfSSL uses to set up an ECDSA Sign.
    NoncePassThrough,
}

#[derive(Debug, Clone, Default)]
pub struct TempKey {
    pub value: [u8; 32],
    pub valid: bool,
    pub source: Option<TempKeySource>,
}

impl TempKey {
    pub fn load_passthrough(&mut self, data: &[u8; 32]) {
        self.value = *data;
        self.valid = true;
        self.source = Some(TempKeySource::NoncePassThrough);
    }
    pub fn clear(&mut self) {
        self.value = [0; 32];
        self.valid = false;
        self.source = None;
    }
}

/// Multi-step SHA-256 context held between SHA init / update / end commands.
#[derive(Default)]
pub struct ShaCtx {
    pub hasher: Option<Sha256>,
}

impl ShaCtx {
    pub fn start(&mut self) {
        self.hasher = Some(Sha256::new());
    }
    pub fn update(&mut self, data: &[u8]) -> bool {
        if let Some(h) = self.hasher.as_mut() {
            h.update(data);
            true
        } else {
            false
        }
    }
    pub fn finish(&mut self, trailing: &[u8]) -> Option<[u8; 32]> {
        let h = self.hasher.take()?;
        let digest = if trailing.is_empty() {
            h.finalize()
        } else {
            let mut h = h;
            h.update(trailing);
            h.finalize()
        };
        Some(digest.into())
    }
    pub fn clear(&mut self) {
        self.hasher = None;
    }
}

#[derive(Default)]
pub struct Session {
    pub tempkey: TempKey,
    pub sha: ShaCtx,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }
    /// Wipe all volatile state (TempKey and any in-progress SHA context).
    /// Called by the TCP server when the host asserts sleep (`0x01`).
    /// Not called on idle or wake — those preserve RAM per the datasheet.
    pub fn volatile_reset(&mut self) {
        self.tempkey.clear();
        self.sha.clear();
    }
}
