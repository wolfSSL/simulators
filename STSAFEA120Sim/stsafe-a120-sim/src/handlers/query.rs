/* query.rs
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

/// Subject tags used by `Query` -- matches services/stsafea/stsafea_put_query.h.
mod tag {
    pub const PRODUCT_DATA: u8 = 0x11;
}

/// Query command -- best-effort minimal implementation.
///
/// The simulator declares `STSE_CONF_USE_STATIC_PERSONALIZATION_INFORMATIONS`
/// in the SDK build, so `stse_init` skips the COMMAND_AUTHORIZATION_CONFIG
/// query path entirely. This handler exists to answer simple PRODUCT_DATA
/// queries used by sanity checks. Other subject tags return INVALID_PARAMETER.
pub fn handle(device: &Device, body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return build_error(status::LENGTH_ERROR);
    }
    match body[0] {
        tag::PRODUCT_DATA => {
            // Real STSAFE-A120 returns a TLV blob. We return the 8-byte
            // serial number prefixed by its length so wolfSSL's
            // `wolfSSL_STSAFE_GetSerial`-style probes (when present) get
            // a deterministic answer. Tests should use this exact shape.
            let mut rsp = Vec::with_capacity(2 + 8);
            rsp.extend_from_slice(&(8u16).to_be_bytes());
            rsp.extend_from_slice(&device.serial_number);
            build_response(status::OK, &rsp)
        }
        _ => build_error(status::INVALID_PARAMETER),
    }
}
