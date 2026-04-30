/* frame.rs
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

/// STSAFE-A wire framing matching `core/stse_frame.c` and
/// `services/stsafea/stsafea_frame_transfer.c` from STSELib v1.1.7.
///
/// Command (host -> device):
///   `[cmd_header (1 or 2 bytes)] [params...] [crc16 2B big-endian]`
///   The 2-byte form is used when the first byte is the extended-command
///   prefix `0x1F`, in which case the second byte is the extended opcode.
///
/// Response (device -> host):
///   `[rsp_header 1B] [length 2B big-endian] [body...] [crc16 2B big-endian]`
///   where `length == body.len() + 2` (the CRC is counted, the length field
///   itself is not). The CRC is computed over `[rsp_header][body]`.
///
/// The response header carries the status code in its low 5 bits; the upper
/// bits encode encryption / authentication flags which are always zero in
/// plain mode (the simulator does not implement host sessions).
use crate::crc::crc16_x25;

pub const STATUS_MASK: u8 = 0x1F;
pub const EXTENDED_PREFIX: u8 = 0x1F;
pub const MAX_FRAME_LENGTH_A120: usize = 752;

/// STSAFE-A status codes (subset). Values match `stse_ReturnCode_t` masked
/// against `STSAFEA_RSP_STATUS_MASK` (0x1F). Anything wolfSSL or STSELib
/// inspects falls in this range; values above 0x1F are wrapped errors.
pub mod status {
    pub const OK: u8 = 0x00;
    pub const COMMUNICATION_ERROR: u8 = 0x01;
    pub const LENGTH_ERROR: u8 = 0x02;
    pub const UNEXPECTED_ERROR: u8 = 0x03;
    pub const INVALID_PARAMETER: u8 = 0x09;
    pub const COMMAND_CODE_NOT_SUPPORTED: u8 = 0x0E;
    pub const CRC_ERROR: u8 = 0x16;
    pub const ACCESS_CONDITION_NOT_SATISFIED: u8 = 0x05;
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadCrc,
    Overflow,
}

/// A parsed inbound command frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Command<'a> {
    pub header: u8,
    /// Extended opcode if `header == EXTENDED_PREFIX`, otherwise `None`.
    pub extended: Option<u8>,
    /// Bytes after the (1- or 2-byte) header and before the trailing CRC.
    pub body: &'a [u8],
}

impl<'a> Command<'a> {
    /// True if this command uses the 2-byte extended header form.
    pub fn is_extended(&self) -> bool {
        self.extended.is_some()
    }
}

/// Parse a raw command frame from the wire.
///
/// `buf` is the entire frame including header and trailing CRC. Returns the
/// header byte(s) and the slice of body bytes (parameters) between them.
/// Validates the trailing CRC-16/X-25 over `[header][body]`.
pub fn parse_command(buf: &[u8]) -> Result<Command<'_>, FrameError> {
    if buf.len() < 3 {
        return Err(FrameError::TooShort);
    }
    if buf.len() > MAX_FRAME_LENGTH_A120 + 2 {
        return Err(FrameError::Overflow);
    }
    let payload_end = buf.len() - 2;
    let received_crc = u16::from_be_bytes([buf[payload_end], buf[payload_end + 1]]);
    let computed = crc16_x25(&buf[..payload_end]);
    if computed != received_crc {
        return Err(FrameError::BadCrc);
    }

    let header = buf[0];
    if header == EXTENDED_PREFIX {
        if buf.len() < 4 {
            return Err(FrameError::TooShort);
        }
        Ok(Command {
            header,
            extended: Some(buf[1]),
            body: &buf[2..payload_end],
        })
    } else {
        Ok(Command {
            header,
            extended: None,
            body: &buf[1..payload_end],
        })
    }
}

/// Build a response frame with `[hdr][len][body][crc]`.
///
/// `status` is the low-5-bits status code; upper bits are zero (plain mode).
/// `body` may be empty for status-only responses (e.g. ACK to Hibernate).
pub fn build_response(status: u8, body: &[u8]) -> Vec<u8> {
    let header = status & STATUS_MASK;
    let length: u16 = (body.len() + 2) as u16;
    let mut out = Vec::with_capacity(1 + 2 + body.len() + 2);
    out.push(header);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);

    // CRC is computed over [header][body] only -- the length field is not
    // part of the CRC scope, matching stsafea_frame_transfer.c which pops
    // the length element off before calling stse_frame_crc16_compute.
    let mut crc_input = Vec::with_capacity(1 + body.len());
    crc_input.push(header);
    crc_input.extend_from_slice(body);
    let crc = crc16_x25(&crc_input);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

/// Build a status-only response (no body), used by handlers reporting errors.
pub fn build_error(status: u8) -> Vec<u8> {
    build_response(status, &[])
}

/// Helper to encode a command frame the same way the host SDK does, used by
/// integration tests that drive the simulator over TCP without going through
/// STSELib.
pub fn build_command(header: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + body.len() + 2);
    frame.push(header);
    frame.extend_from_slice(body);
    let crc = crc16_x25(&frame);
    frame.extend_from_slice(&crc.to_be_bytes());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let body = [0x11, 0x22, 0x33];
        let frame = build_command(0x02, &body);
        let cmd = parse_command(&frame).unwrap();
        assert_eq!(cmd.header, 0x02);
        assert_eq!(cmd.extended, None);
        assert_eq!(cmd.body, &body);
    }

    #[test]
    fn extended_header_split() {
        let body = [0xAA];
        let mut raw = Vec::new();
        raw.push(EXTENDED_PREFIX);
        raw.push(0x05);
        raw.extend_from_slice(&body);
        let crc = crc16_x25(&raw);
        raw.extend_from_slice(&crc.to_be_bytes());
        let cmd = parse_command(&raw).unwrap();
        assert_eq!(cmd.header, EXTENDED_PREFIX);
        assert_eq!(cmd.extended, Some(0x05));
        assert_eq!(cmd.body, &body);
    }

    #[test]
    fn rejects_bad_crc() {
        let mut frame = build_command(0x02, &[0x00, 0x10]);
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert_eq!(parse_command(&frame), Err(FrameError::BadCrc));
    }

    #[test]
    fn response_length_field_excludes_itself_includes_crc() {
        let resp = build_response(status::OK, &[0xDE, 0xAD]);
        // [hdr][len_hi][len_lo][body][crc_hi][crc_lo] -> 7 bytes total
        assert_eq!(resp.len(), 7);
        assert_eq!(resp[0], 0x00);
        // length = body_len(2) + crc(2) = 4
        assert_eq!(u16::from_be_bytes([resp[1], resp[2]]), 4);
        let crc_in = [resp[0], resp[3], resp[4]];
        let crc = u16::from_be_bytes([resp[5], resp[6]]);
        assert_eq!(crc, crc16_x25(&crc_in));
    }

    #[test]
    fn build_error_has_empty_body_and_correct_length() {
        let resp = build_error(status::INVALID_PARAMETER);
        assert_eq!(resp.len(), 5);
        assert_eq!(resp[0] & STATUS_MASK, status::INVALID_PARAMETER);
        // length = 0 (body) + 2 (crc) = 2
        assert_eq!(u16::from_be_bytes([resp[1], resp[2]]), 2);
    }
}
