/* frame.rs
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

/// TROPIC01 L2 frame layout matches the structs in
/// `libtropic/src/lt_l2_api_structs.h` and the polling protocol in
/// `libtropic/src/lt_l1.c`:
///
///   Request  (host -> chip): [REQ_ID(1B)] [REQ_LEN(1B)] [REQ_DATA(REQ_LEN)] [CRC(2B BE)]
///   Response (chip -> host): [STATUS(1B)] [RSP_LEN(1B)] [RSP_DATA(RSP_LEN)] [CRC(2B BE)]
///
/// The response is preceded on the SPI wire by a CHIP_STATUS byte that
/// `lt_l1.c` reads in its first 1-byte transfer. CHIP_STATUS is not part
/// of the L2 frame proper -- it's the chip's "ready / startup / alarm"
/// signalling -- so this module deals only with `[STATUS][RSP_LEN][DATA][CRC]`.
/// `spi.rs` prepends the CHIP_STATUS byte during the polled-read flow.
///
/// CRC is the libtropic `crc16` variant (poly 0x8005, init 0x0000, no
/// reflection apart from the final big-endian byte swap), computed over
/// `[REQ_ID][REQ_LEN][REQ_DATA]` for requests and `[STATUS][RSP_LEN][DATA]`
/// for responses.
use crate::crc::{crc16, append_crc};

/// `TR01_L1_GET_RESPONSE_REQ_ID` in libtropic's `lt_l1.h`. Reserved as the
/// "poll the chip for a pending response" magic; can never appear as a
/// real REQ_ID on a write.
pub const GET_RESPONSE_REQ_ID: u8 = 0xAA;

/// `TR01_L2_CHUNK_MAX_DATA_SIZE` from `libtropic_common.h` - max payload
/// the chip will produce in a single L2 response chunk.
pub const MAX_L2_DATA_SIZE: usize = 252;

/// Max bytes for a complete L2 frame: REQ_ID + REQ_LEN + DATA + CRC.
pub const MAX_L2_FRAME_SIZE: usize = 1 + 1 + MAX_L2_DATA_SIZE + 2;

/// L2 STATUS byte values, matching `TR01_L2_STATUS_*` in
/// `libtropic/src/lt_l2_frame_check.h`. The chip puts one of these in the
/// second byte of the polled-read response (after the CHIP_STATUS byte).
pub mod status {
    /// `TR01_L2_STATUS_REQUEST_OK = 0x01` - chip accepted a plain L2 request
    /// (e.g. GET_INFO, HANDSHAKE) and the reply payload follows.
    pub const REQUEST_OK: u8 = 0x01;
    /// `TR01_L2_STATUS_RESULT_OK = 0x02` - chip executed an Encrypted_Cmd
    /// L3 command and the encrypted reply follows.
    pub const RESULT_OK: u8 = 0x02;
    /// `TR01_L2_STATUS_REQUEST_CONT = 0x03` - more chunks expected in this
    /// request.
    pub const REQUEST_CONT: u8 = 0x03;
    /// `TR01_L2_STATUS_RESULT_CONT = 0x04` - more chunks of response to come.
    pub const RESULT_CONT: u8 = 0x04;
    /// `TR01_L2_STATUS_RESP_DISABLED = 0x78` - the request's REQ_ID is
    /// disabled in the current chip mode (e.g. APP-mode-only command in
    /// startup mode).
    pub const RESP_DISABLED: u8 = 0x78;
    /// `TR01_L2_STATUS_HSK_ERR = 0x79` - handshake failed.
    pub const HSK_ERR: u8 = 0x79;
    /// `TR01_L2_STATUS_NO_SESSION = 0x7A` - Encrypted_Cmd issued without an
    /// open Secure Channel.
    pub const NO_SESSION: u8 = 0x7A;
    /// `TR01_L2_STATUS_TAG_ERR = 0x7B` - AES-GCM tag failed.
    pub const TAG_ERR: u8 = 0x7B;
    /// `TR01_L2_STATUS_CRC_ERR = 0x7C` - chip computed a different CRC over
    /// the inbound request frame.
    pub const CRC_ERR: u8 = 0x7C;
    /// `TR01_L2_STATUS_UNKNOWN_ERR = 0x7E` - REQ_ID not recognised.
    pub const UNKNOWN_ERR: u8 = 0x7E;
    /// `TR01_L2_STATUS_GEN_ERR = 0x7F` - unspecified failure.
    pub const GEN_ERR: u8 = 0x7F;
    /// `TR01_L2_STATUS_NO_RESP = 0xFF` - chip has nothing to give yet, host
    /// should re-poll. We never embed this in a built response; the SPI
    /// emulator surfaces it directly during the polling loop instead.
    pub const NO_RESP: u8 = 0xFF;
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    LenMismatch,
    BadCrc,
    Overflow,
}

/// A parsed L2 request frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub req_id: u8,
    pub data: &'a [u8],
}

/// Parse an L2 request frame from the host. `buf` is the entire frame
/// including REQ_ID, REQ_LEN, REQ_DATA, CRC.
pub fn parse_request(buf: &[u8]) -> Result<Request<'_>, FrameError> {
    if buf.len() < 4 {
        // REQ_ID + REQ_LEN + 0 data + CRC(2)
        return Err(FrameError::TooShort);
    }
    if buf.len() > MAX_L2_FRAME_SIZE {
        return Err(FrameError::Overflow);
    }
    let req_id = buf[0];
    let req_len = buf[1] as usize;
    if buf.len() != 1 + 1 + req_len + 2 {
        return Err(FrameError::LenMismatch);
    }
    let crc_offset = 2 + req_len;
    let received_crc = u16::from_be_bytes([buf[crc_offset], buf[crc_offset + 1]]);
    let computed = crc16(&buf[..crc_offset]);
    if computed != received_crc {
        return Err(FrameError::BadCrc);
    }
    Ok(Request {
        req_id,
        data: &buf[2..crc_offset],
    })
}

/// Build an L2 response frame `[STATUS][RSP_LEN][DATA][CRC]`. CHIP_STATUS
/// is added separately by the SPI emulator when serving the polled-read
/// transaction.
pub fn build_response(status: u8, data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= MAX_L2_DATA_SIZE,
        "L2 response data exceeds chunk size"
    );
    let mut out = Vec::with_capacity(2 + data.len() + 2);
    out.push(status);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    append_crc(&mut out);
    out
}

/// Convenience wrapper used by tests + by the SPI emulator's "format your
/// own L2 request" path: builds `[REQ_ID][REQ_LEN][DATA][CRC]`.
pub fn build_request(req_id: u8, data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= MAX_L2_DATA_SIZE,
        "L2 request data exceeds chunk size"
    );
    let mut out = Vec::with_capacity(2 + data.len() + 2);
    out.push(req_id);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    append_crc(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let body = [0x11, 0x22, 0x33];
        let frame = build_request(0x01, &body);
        let req = parse_request(&frame).unwrap();
        assert_eq!(req.req_id, 0x01);
        assert_eq!(req.data, &body);
    }

    #[test]
    fn rejects_bad_crc() {
        let mut frame = build_request(0x01, &[0x00, 0x00]);
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert_eq!(parse_request(&frame), Err(FrameError::BadCrc));
    }

    #[test]
    fn rejects_truncated() {
        let frame = [0x01, 0x05, 0x00, 0x00];
        assert_eq!(parse_request(&frame), Err(FrameError::LenMismatch));
    }

    #[test]
    fn response_layout() {
        let resp = build_response(status::REQUEST_OK, &[0xDE, 0xAD]);
        assert_eq!(resp.len(), 1 + 1 + 2 + 2);
        assert_eq!(resp[0], status::REQUEST_OK);
        assert_eq!(resp[1], 2);
        assert_eq!(&resp[2..4], &[0xDE, 0xAD]);
        // CRC is over [STATUS][RSP_LEN][DATA].
        let expected = crc16(&resp[..4]);
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), expected);
    }

    #[test]
    fn empty_response() {
        let resp = build_response(status::REQUEST_OK, &[]);
        assert_eq!(resp.len(), 4);
        assert_eq!(resp[1], 0);
    }
}
