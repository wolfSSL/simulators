/* atca.rs
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

/// ATCA wire protocol framing for the ATECC608A.
///
/// A command packet sent after word-address `0x03` has the form:
///   [count][opcode][p1][p2_lo][p2_hi][data...][crc_lo][crc_hi]
/// where `count` is the total length including itself and the trailing CRC,
/// i.e. `count = 7 + data.len()`.
///
/// A response packet has the form:
///   [count][data...][crc_lo][crc_hi]
/// with `count = 3 + data.len()`. A 1-byte status response (e.g. Lock success)
/// uses `count = 4` and `data = [status]`.
use crate::crc::{crc16, crc16_le};

/// Minimum command packet length: count + opcode + p1 + p2(2) + crc(2) = 7.
pub const MIN_CMD_LEN: usize = 7;

/// Standard ATCA status codes returned in 1-byte response bodies.
pub mod status {
    pub const SUCCESS: u8 = 0x00;
    pub const MISCOMPARE: u8 = 0x01;
    pub const PARSE_ERROR: u8 = 0x03;
    pub const EXECUTION_ERROR: u8 = 0x0F;
    pub const AFTER_WAKE: u8 = 0x11;
    pub const CRC_ERROR: u8 = 0xFF;
}

/// The 4-byte sequence an ATECC returns on wake.
/// `{count=0x04, AFTER_WAKE=0x11, crc_lo=0x33, crc_hi=0x43}`.
pub const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

/// A parsed ATCA command packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub opcode: u8,
    pub p1: u8,
    pub p2: u16,
    pub data: Vec<u8>,
}

impl Command {
    /// Parse a raw command packet starting at the `count` byte (i.e. after the
    /// 0x03 word-address byte has already been consumed).
    ///
    /// Returns `Err(status_byte)` with the appropriate ATCA error code if the
    /// packet is malformed or has a bad CRC.
    pub fn parse(packet: &[u8]) -> Result<Self, u8> {
        if packet.len() < MIN_CMD_LEN {
            return Err(status::PARSE_ERROR);
        }
        let count = packet[0] as usize;
        if count != packet.len() || count < MIN_CMD_LEN {
            return Err(status::PARSE_ERROR);
        }
        let crc_start = count - 2;
        let expected = crc16(&packet[..crc_start]);
        let got = u16::from_le_bytes([packet[crc_start], packet[crc_start + 1]]);
        if expected != got {
            return Err(status::CRC_ERROR);
        }
        let opcode = packet[1];
        let p1 = packet[2];
        let p2 = u16::from_le_bytes([packet[3], packet[4]]);
        let data = packet[5..crc_start].to_vec();
        Ok(Self { opcode, p1, p2, data })
    }
}

/// Build a full response packet: `[count][body][crc_lo][crc_hi]`.
pub fn build_response(body: &[u8]) -> Vec<u8> {
    let count = 1 + body.len() + 2;
    assert!(count <= 0xFF, "response too large: {} bytes", count);
    let mut out = Vec::with_capacity(count);
    out.push(count as u8);
    out.extend_from_slice(body);
    let crc = crc16_le(&out);
    out.extend_from_slice(&crc);
    out
}

/// Convenience: build a 1-byte status response (count=4).
pub fn status_response(status: u8) -> Vec<u8> {
    build_response(&[status])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cmd(opcode: u8, p1: u8, p2: u16, data: &[u8]) -> Vec<u8> {
        let count = (7 + data.len()) as u8;
        let mut pkt = vec![count, opcode, p1, (p2 & 0xFF) as u8, (p2 >> 8) as u8];
        pkt.extend_from_slice(data);
        let crc = crc16_le(&pkt);
        pkt.extend_from_slice(&crc);
        pkt
    }

    #[test]
    fn parse_info_command() {
        let pkt = make_cmd(0x30, 0x00, 0x0000, &[]);
        let cmd = Command::parse(&pkt).expect("valid info command must parse");
        assert_eq!(cmd.opcode, 0x30);
        assert_eq!(cmd.p1, 0x00);
        assert_eq!(cmd.p2, 0x0000);
        assert!(cmd.data.is_empty());
    }

    #[test]
    fn parse_with_data_payload() {
        let payload = b"hello-world!";
        let pkt = make_cmd(0x47, 0x01, 0x1234, payload);
        let cmd = Command::parse(&pkt).unwrap();
        assert_eq!(cmd.opcode, 0x47);
        assert_eq!(cmd.p1, 0x01);
        assert_eq!(cmd.p2, 0x1234);
        assert_eq!(cmd.data, payload);
    }

    #[test]
    fn reject_bad_crc() {
        let mut pkt = make_cmd(0x30, 0x00, 0x0000, &[]);
        // Flip one CRC byte
        let last = pkt.len() - 1;
        pkt[last] ^= 0xFF;
        assert_eq!(Command::parse(&pkt), Err(status::CRC_ERROR));
    }

    #[test]
    fn reject_bad_count() {
        let mut pkt = make_cmd(0x30, 0x00, 0x0000, &[]);
        pkt[0] = pkt[0].wrapping_add(1);
        assert_eq!(Command::parse(&pkt), Err(status::PARSE_ERROR));
    }

    #[test]
    fn reject_too_short() {
        assert_eq!(Command::parse(&[]), Err(status::PARSE_ERROR));
        assert_eq!(Command::parse(&[0x06, 0x30, 0, 0, 0, 0]), Err(status::PARSE_ERROR));
    }

    #[test]
    fn response_round_trip() {
        let resp = build_response(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(resp[0], 6); // count = 1 + 3 + 2
        assert_eq!(&resp[1..4], &[0xAA, 0xBB, 0xCC]);
        let crc = crc16_le(&resp[..4]);
        assert_eq!(&resp[4..6], &crc);
    }

    #[test]
    fn status_response_is_four_bytes() {
        let r = status_response(status::SUCCESS);
        assert_eq!(r.len(), 4);
        assert_eq!(r[0], 4);
        assert_eq!(r[1], 0x00);
    }
}
