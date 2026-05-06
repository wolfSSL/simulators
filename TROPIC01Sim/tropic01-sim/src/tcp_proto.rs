/* tcp_proto.rs
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

/// libtropic's "TROPIC01 Model" TCP framing used by `hal/posix/tcp/`.
/// Each message on the wire is `[tag (1B)] [len (2B little-endian)] [payload (len B)]`.
/// The host (libtropic) and the server (this simulator) speak the same
/// frame in both directions; the server echoes the tag back.
///
/// The byte order of `len` follows the packed C struct in
/// `libtropic_port_posix_tcp.h::lt_posix_tcp_buffer_t` -- on every platform
/// libtropic actually targets via this HAL (Linux x86_64 / aarch64 / armv7),
/// that means little-endian.
use std::io::{self, Read, Write};

pub const TAG_AND_LEN_SIZE: usize = 3;
pub const MAX_PAYLOAD_LEN: usize = 1 + 1 + 252 + 2; // TR01_L2_MAX_FRAME_SIZE

/// Tags from `libtropic_port_posix_tcp.h::lt_posix_tcp_tag_t`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpTag {
    SpiDriveCsnLow = 0x01,
    SpiDriveCsnHigh = 0x02,
    SpiSend = 0x03,
    PowerOn = 0x04,
    PowerOff = 0x05,
    Wait = 0x06,
    ResetTarget = 0x10,
    Invalid = 0xFD,
    Unsupported = 0xFE,
}

impl TcpTag {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => TcpTag::SpiDriveCsnLow,
            0x02 => TcpTag::SpiDriveCsnHigh,
            0x03 => TcpTag::SpiSend,
            0x04 => TcpTag::PowerOn,
            0x05 => TcpTag::PowerOff,
            0x06 => TcpTag::Wait,
            0x10 => TcpTag::ResetTarget,
            0xFD => TcpTag::Invalid,
            0xFE => TcpTag::Unsupported,
            _ => TcpTag::Invalid,
        }
    }
}

/// One framed message read from / written to the socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpFrame {
    pub tag: u8,
    pub payload: Vec<u8>,
}

impl TcpFrame {
    pub fn new(tag: TcpTag, payload: Vec<u8>) -> Self {
        Self {
            tag: tag as u8,
            payload,
        }
    }

    /// Read one frame off the wire. Returns Ok(None) on clean EOF.
    pub fn read_from<R: Read>(r: &mut R) -> io::Result<Option<Self>> {
        let mut header = [0u8; TAG_AND_LEN_SIZE];
        match r.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let tag = header[0];
        let len = u16::from_le_bytes([header[1], header[2]]) as usize;
        if len > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("oversized TCP frame: len={len}"),
            ));
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut payload)?;
        }
        Ok(Some(Self { tag, payload }))
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "TCP frame payload too large: {} > {}",
                    self.payload.len(),
                    MAX_PAYLOAD_LEN
                ),
            ));
        }
        let mut header = [0u8; TAG_AND_LEN_SIZE];
        header[0] = self.tag;
        let len = self.payload.len() as u16;
        header[1..3].copy_from_slice(&len.to_le_bytes());
        w.write_all(&header)?;
        if !self.payload.is_empty() {
            w.write_all(&self.payload)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_csn_low() {
        let frame = TcpFrame::new(TcpTag::SpiDriveCsnLow, vec![]);
        let mut buf = Vec::new();
        frame.write_to(&mut buf).unwrap();
        assert_eq!(buf, vec![0x01, 0x00, 0x00]);

        let mut cursor = Cursor::new(buf);
        let parsed = TcpFrame::read_from(&mut cursor).unwrap().unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn round_trip_spi_send() {
        let frame = TcpFrame::new(TcpTag::SpiSend, vec![0xAA, 0x01, 0x02, 0x03]);
        let mut buf = Vec::new();
        frame.write_to(&mut buf).unwrap();
        assert_eq!(buf[0], 0x03);
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 4);
        assert_eq!(&buf[3..], &[0xAA, 0x01, 0x02, 0x03]);

        let mut cursor = Cursor::new(buf);
        let parsed = TcpFrame::read_from(&mut cursor).unwrap().unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn read_eof_returns_none() {
        let mut empty = Cursor::new(Vec::new());
        assert!(TcpFrame::read_from(&mut empty).unwrap().is_none());
    }

    #[test]
    fn write_rejects_oversized_payload() {
        let frame = TcpFrame {
            tag: TcpTag::SpiSend as u8,
            payload: vec![0u8; MAX_PAYLOAD_LEN + 1],
        };
        let mut sink: Vec<u8> = Vec::new();
        let err = frame.write_to(&mut sink).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
