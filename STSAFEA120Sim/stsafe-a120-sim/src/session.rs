/* session.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STSAFEA120Sim.
 *
 * STSAFEA120Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STSAFEA120Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

use p256::SecretKey;

/// Per-connection volatile state for the STSAFE-A120 simulator.
///
/// In plain mode the only volatile thing the device tracks across a single
/// host connection is the ECDHE ephemeral key returned from the
/// `Generate ECDHE Key Pair` extended command -- subsequent `Establish Key`
/// calls against slot 0xFF use it. We don't model the volatile-KEK / host
/// session machinery because the simulator runs in plain mode (no host MAC,
/// no AES-CBC C-MAC).
#[derive(Default)]
pub struct Session {
    pub ecdhe_private: Option<SecretKey>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.ecdhe_private = None;
    }
}
