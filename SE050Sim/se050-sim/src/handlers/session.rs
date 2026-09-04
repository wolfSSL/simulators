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
use crate::applet::AppletVersion;
use crate::object_store::ObjectStore;

/// SE050 applet AID
pub(crate) const SE050_AID: [u8; 16] = [
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
];

/// Supplementary Security Domain selected by NXP's Platform SCP03 key
/// rotation example before it authenticates and sends GlobalPlatform PUT KEY.
pub(crate) const SSD_AID: [u8; 11] = [
    0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03,
];

pub(crate) fn selects_ssd(apdu: &ParsedApdu) -> bool {
    apdu.data == SSD_AID
}

/// Handle SELECT applet command (CLA=0x00, INS=0xA4).
/// The response is raw bytes (not TLV-wrapped), matching what the driver
/// expects in receive_apdu_raw. The 7-byte body is the same version
/// blob GetVersion returns; the middleware parses it to decide applet
/// compatibility ("Compiled for ... Got older ..." aborts).
pub fn handle_select(
    apdu: &ParsedApdu,
    _store: &mut ObjectStore,
    version: AppletVersion,
) -> ApduResponse {
    // Verify the AID matches
    if apdu.data == SE050_AID {
        ApduResponse::success_with_data(version.version_bytes().to_vec())
    } else if selects_ssd(apdu) {
        ApduResponse::success()
    } else {
        ApduResponse::error(0x6A82) // File not found
    }
}
