/* read.rs
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

use crate::frame::{build_error, build_response, status};
use crate::object_store::Device;

/// Read zone command.
///
/// Wire (cmd body):
///   `[option 1B] [zone_index 1B] [offset 2B BE] [length 2B BE]`
///
///   (Note: `stsafea_read_data_zone` calls `stse_frame_element_swap_byte_order`
///    on the offset and length elements before transmission, so even though
///    the C struct is little-endian on the host, the bytes on the wire are
///    big-endian. STSELib's `zone_index` parameter is `PLAT_UI32` but
///    only the low byte is meaningful for STSAFE-A120 -- the upper bytes are
///    sent as zero.)
///
/// Wire (rsp body): `[data ... read_length bytes]`
///
/// Service: `stsafea_read_data_zone` --
/// services/stsafea/stsafea_data_partition.c.
pub fn handle(device: &Device, body: &[u8]) -> Vec<u8> {
    // The STSELib zone_index is sent as a 4-byte little-endian word with
    // no byte-order swap (`stsafea_frame_element_swap_byte_order` is only
    // invoked on offset and length). On real silicon the device parses
    // out the low byte of zone_index. We accept either 1 or 4 bytes for
    // robustness.
    if body.len() < 1 + 1 + 2 + 2 {
        return build_error(status::LENGTH_ERROR);
    }
    let _option = body[0];
    let zone_index = body[1];
    let mut p = 2;
    if body.len() == 1 + 4 + 2 + 2 {
        // Caller pushed a 4-byte zone_index.
        p = 1 + 4;
    }
    let offset = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    let length = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;

    let Some(zone) = device.data_zones.get(&zone_index) else {
        return build_error(status::INVALID_PARAMETER);
    };
    if offset.saturating_add(length) > zone.data.len() {
        return build_error(status::INVALID_PARAMETER);
    }
    let slice = &zone.data[offset..offset + length];
    build_response(status::OK, slice)
}
