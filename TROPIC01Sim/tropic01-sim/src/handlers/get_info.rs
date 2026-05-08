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

/// L2 GET_INFO (REQ_ID = 0x01). Wire layout from
/// `lt_l2_api_structs.h::lt_l2_get_info_req_t`:
///
///   [object_id (1B)] [block_index (1B)]
///
/// `object_id` selects which artefact to return:
///   0x00 X509_CERTIFICATE -- chip cert (block_index addresses 128B chunks)
///   0x01 CHIP_ID
///   0x02 RISCV_FW_VERSION
///   0x04 SPECT_FW_VERSION
///   0xB0 FW_BANK (start-up mode only; not modelled)
///
/// All return data lands in `[STATUS=REQUEST_OK][RSP_LEN][object][CRC]`.
use crate::frame::{build_response, status};
use crate::object_store::Device;

const OBJECT_ID_X509_CERT: u8 = 0x00;
const OBJECT_ID_CHIP_ID: u8 = 0x01;
const OBJECT_ID_RISCV_FW: u8 = 0x02;
const OBJECT_ID_SPECT_FW: u8 = 0x04;

/// Each GET_INFO chunk is at most 128B (`TR01_L2_CHUNK_MAX_DATA_SIZE` is
/// 252B for the wire frame, but the cert chunking convention used by the
/// host is 128B per block_index).
const CHUNK_SIZE: usize = 128;

/// Fake firmware version emitted as RISCV_FW_VERSION / SPECT_FW_VERSION.
/// Top bit clear means "APP mode" (per the doc comment in lt_l2_api_structs.h).
const FAKE_FW_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

pub fn handle(device: &Device, body: &[u8]) -> Vec<u8> {
    if body.len() != 2 {
        return build_response(status::GEN_ERR, &[]);
    }
    let object_id = body[0];
    let block_index = body[1] as usize;

    match object_id {
        OBJECT_ID_X509_CERT => respond_chunked(&device.cert_store, block_index),
        OBJECT_ID_CHIP_ID => {
            // Pad chip_id to a fixed 128B size; the host receives whatever
            // RSP_LEN says, so emitting just the 12-byte ID is also valid.
            let mut out = vec![0u8; 128];
            out[..device.chip_id.len()].copy_from_slice(&device.chip_id);
            build_response(status::REQUEST_OK, &out)
        }
        OBJECT_ID_RISCV_FW | OBJECT_ID_SPECT_FW => {
            build_response(status::REQUEST_OK, &FAKE_FW_VERSION)
        }
        _ => build_response(status::UNKNOWN_ERR, &[]),
    }
}

fn respond_chunked(blob: &[u8], block_index: usize) -> Vec<u8> {
    // libtropic's `lt_get_info_cert_store` requires every chunk to be
    // exactly 128 bytes (it errors out on any other rsp_len). We always
    // emit a full 128B chunk; if the block is past the end of the blob
    // we just emit zeros for that range. The host's loop terminates
    // based on the cert lengths in the header, not the chunk contents.
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let start = block_index.saturating_mul(CHUNK_SIZE);
    if start < blob.len() {
        let end = (start + CHUNK_SIZE).min(blob.len());
        chunk[..end - start].copy_from_slice(&blob[start..end]);
    }
    build_response(status::REQUEST_OK, &chunk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::status;
    use crate::object_store::Store;

    #[test]
    fn chip_id_round_trip() {
        let store = Store::fresh();
        let resp = handle(&store.device, &[OBJECT_ID_CHIP_ID, 0]);
        // [STATUS][RSP_LEN][DATA(128)][CRC(2)]
        assert_eq!(resp[0], status::REQUEST_OK);
        assert_eq!(resp[1], 128);
        assert_eq!(&resp[2..2 + 12], &store.device.chip_id);
    }

    #[test]
    fn cert_chunk_zero_returns_full_128() {
        let store = Store::fresh();
        let resp = handle(&store.device, &[OBJECT_ID_X509_CERT, 0]);
        assert_eq!(resp[0], status::REQUEST_OK);
        // Always exactly 128 bytes, regardless of where the cert ends.
        assert_eq!(resp[1] as usize, CHUNK_SIZE);
        // First chunk starts with the cert-store header (version=1, num_certs=4).
        assert_eq!(resp[2], 1);
        assert_eq!(resp[3], 4);
    }

    #[test]
    fn cert_chunk_past_end_returns_zeros() {
        let store = Store::fresh();
        let resp = handle(&store.device, &[OBJECT_ID_X509_CERT, 99]);
        assert_eq!(resp[0], status::REQUEST_OK);
        assert_eq!(resp[1] as usize, CHUNK_SIZE);
        // All zeros past the end -- the host's loop would have stopped
        // already based on the cert lengths header.
        assert!(resp[2..2 + CHUNK_SIZE].iter().all(|&b| b == 0));
    }

    #[test]
    fn fw_version_returns_4_bytes() {
        let store = Store::fresh();
        let resp = handle(&store.device, &[OBJECT_ID_RISCV_FW, 0]);
        assert_eq!(resp[0], status::REQUEST_OK);
        assert_eq!(resp[1], 4);
    }

    #[test]
    fn unknown_object_returns_unknown_err() {
        let store = Store::fresh();
        let resp = handle(&store.device, &[0xFE, 0]);
        assert_eq!(resp[0], status::UNKNOWN_ERR);
    }
}
