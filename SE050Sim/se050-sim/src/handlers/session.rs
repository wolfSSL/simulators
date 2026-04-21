/* session.rs
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

use crate::apdu::{ApduResponse, ParsedApdu};
use crate::object_store::ObjectStore;

/// SE050 applet AID
const SE050_AID: [u8; 16] = [
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
];

/// Simulated version info: major=7, minor=2, patch=0, features=0x6FFF, securebox=0x010B
const APP_VERSION: [u8; 7] = [0x07, 0x02, 0x00, 0x6F, 0xFF, 0x01, 0x0B];

/// Handle SELECT applet command (CLA=0x00, INS=0xA4).
/// The response is raw bytes (not TLV-wrapped), matching what the driver
/// expects in receive_apdu_raw.
pub fn handle_select(apdu: &ParsedApdu, _store: &mut ObjectStore) -> ApduResponse {
    // Verify the AID matches
    if apdu.data.len() >= 16 && apdu.data[..16] == SE050_AID {
        // Return 7-byte version info + SW 0x9000
        ApduResponse::success_with_data(APP_VERSION.to_vec())
    } else {
        ApduResponse::error(0x6A82) // File not found
    }
}
