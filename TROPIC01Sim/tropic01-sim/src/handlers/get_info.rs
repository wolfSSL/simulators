/* get_info.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of TROPIC01Sim.
 *
 * TROPIC01Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * TROPIC01Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

//! L2 Get_Info_Req (REQ_ID 0x01): `[object_id][block_index]`.
//!
//! | object_id | object                         | notes                       |
//! |-----------|--------------------------------|-----------------------------|
//! | 0x00      | X.509 certificate store        | 128 B blocks 0..=29         |
//! | 0x01      | CHIP_ID (128 B)                |                             |
//! | 0x02      | RISC-V FW version (4 B)        | bootloader version in       |
//! |           |                                | Maintenance mode            |
//! | 0x04      | SPECT FW version (4 B)         |                             |
//! | 0xB0      | FW bank header                 | Maintenance mode only;      |
//! |           |                                | block_index selects bank    |
//!
//! Anything else, a block index past the certificate store, or FW_BANK in
//! Application mode is GEN_ERR (as on the bench chip).

use sha2::{Digest, Sha256};

use crate::certs::{CERT_STORE_BLOCKS, CERT_STORE_BLOCK_SIZE};
use crate::frame::{build_response, status};
use crate::object_store::Device;

pub const OBJECT_X509_CERTIFICATE: u8 = 0x00;
pub const OBJECT_CHIP_ID: u8 = 0x01;
pub const OBJECT_RISCV_FW_VERSION: u8 = 0x02;
pub const OBJECT_SPECT_FW_VERSION: u8 = 0x04;
pub const OBJECT_FW_BANK: u8 = 0xb0;

const BANK_FW1: u8 = 0x01;
const BANK_FW2: u8 = 0x02;
const BANK_SPECT1: u8 = 0x11;
const BANK_SPECT2: u8 = 0x12;

pub fn handle(device: &Device, maintenance: bool, object_id: u8, block: u8) -> Vec<u8> {
    let p = device.personality;
    match object_id {
        OBJECT_X509_CERTIFICATE => {
            let block = block as usize;
            if block >= CERT_STORE_BLOCKS {
                return build_response(status::GEN_ERR, &[]);
            }
            let mut chunk = vec![0u8; CERT_STORE_BLOCK_SIZE];
            let start = block * CERT_STORE_BLOCK_SIZE;
            if start < device.cert_store.len() {
                let end = (start + CERT_STORE_BLOCK_SIZE).min(device.cert_store.len());
                chunk[..end - start].copy_from_slice(&device.cert_store[start..end]);
            }
            build_response(status::REQUEST_OK, &chunk)
        }
        OBJECT_CHIP_ID => build_response(status::REQUEST_OK, &device.chip_id),
        OBJECT_RISCV_FW_VERSION => {
            let v = if maintenance {
                p.bootloader_version()
            } else {
                p.riscv_fw_version()
            };
            build_response(status::REQUEST_OK, &v)
        }
        OBJECT_SPECT_FW_VERSION => {
            let v = if maintenance {
                p.bootloader_spect_version()
            } else {
                p.spect_fw_version()
            };
            build_response(status::REQUEST_OK, &v)
        }
        OBJECT_FW_BANK if maintenance => match block {
            BANK_FW1 => build_response(
                status::REQUEST_OK,
                &bank_header(device, 1, p.riscv_fw_version(), 0x5ec0),
            ),
            BANK_SPECT1 => build_response(
                status::REQUEST_OK,
                &bank_header(device, 2, p.spect_fw_version(), 0x2350),
            ),
            BANK_FW2 | BANK_SPECT2 => {
                build_response(status::REQUEST_OK, &vec![0xff; p.fw_bank_header_len()])
            }
            _ => build_response(status::REQUEST_OK, &[]),
        },
        _ => build_response(status::GEN_ERR, &[]),
    }
}

/// Synthesized header of an occupied firmware bank, in the bootloader 1.x
/// (20 B) or 2.x (52 B) layout. Hash fields are derived from the chip ID so
/// they are stable per simulated device.
fn bank_header(device: &Device, fw_type: u8, version: [u8; 4], size: u32) -> Vec<u8> {
    let digest = Sha256::new()
        .chain_update(&device.chip_id)
        .chain_update([fw_type])
        .finalize();
    let mut h = Vec::with_capacity(52);
    if device.personality.fw_bank_header_len() == 20 {
        h.extend_from_slice(&[fw_type, 0, 0, 0]);
        h.extend_from_slice(&version);
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&digest[..8]);
    } else {
        h.extend_from_slice(&(fw_type as u16).to_le_bytes());
        h.push(0);
        h.push(2);
        h.extend_from_slice(&version);
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&digest[..4]);
        h.extend_from_slice(&digest);
        h.extend_from_slice(&[0, 0, 0, 0]);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::Store;

    #[test]
    fn chip_id_is_128_bytes() {
        let store = Store::fresh();
        let resp = handle(&store.device, false, OBJECT_CHIP_ID, 0);
        assert_eq!(resp[0], status::REQUEST_OK);
        assert_eq!(resp[1], 128);
        assert_eq!(&resp[2..130], store.device.chip_id.as_slice());
    }

    #[test]
    fn cert_blocks_cover_3840_bytes() {
        let store = Store::fresh();
        let resp = handle(&store.device, false, OBJECT_X509_CERTIFICATE, 0);
        assert_eq!(resp[1] as usize, CERT_STORE_BLOCK_SIZE);
        assert_eq!(resp[2], 1);
        assert_eq!(resp[3], 4);
        assert_eq!(
            handle(&store.device, false, OBJECT_X509_CERTIFICATE, 29)[0],
            status::REQUEST_OK
        );
        assert_eq!(
            handle(&store.device, false, OBJECT_X509_CERTIFICATE, 30)[0],
            status::GEN_ERR
        );
    }

    #[test]
    fn fw_bank_only_in_maintenance() {
        let store = Store::fresh();
        assert_eq!(
            handle(&store.device, false, OBJECT_FW_BANK, 1)[0],
            status::GEN_ERR
        );
        let r = handle(&store.device, true, OBJECT_FW_BANK, 1);
        assert_eq!(r[0], status::REQUEST_OK);
        assert_eq!(r[1], 20);
        assert_eq!(handle(&store.device, true, OBJECT_FW_BANK, 3)[1], 0);
    }

    #[test]
    fn unknown_object_is_gen_err() {
        let store = Store::fresh();
        for id in [0x03, 0x05, 0xff] {
            assert_eq!(handle(&store.device, false, id, 0)[0], status::GEN_ERR);
        }
    }
}
