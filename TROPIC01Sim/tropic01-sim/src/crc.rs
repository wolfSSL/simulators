/* crc.rs
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

/// TROPIC01 CRC-16 used by libtropic's `lt_crc16.c`:
///   poly = 0x8005, init = 0x0000, refin = false, refout = false (the
///   final byte-swap is just so the result is serialized big-endian),
///   xorout = 0x0000.
///
/// Important: this is NOT CRC-16/X-25. The reflection lives only in the
/// final return value (`crc << 8 | crc >> 8`) so the wire bytes match the
/// big-endian CRC the chip emits and the host expects.
pub fn crc16(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in buf {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x8005;
            } else {
                crc <<= 1;
            }
        }
    }
    (crc << 8) | (crc >> 8)
}

/// Append the 2-byte CRC to `frame` (matches the `add_crc` helper in
/// `lt_crc16.c` — CRC is computed over `[REQ_ID][REQ_LEN][REQ_DATA]` and
/// emitted as `[crc_hi][crc_lo]`).
pub fn append_crc(frame: &mut Vec<u8>) {
    let crc = crc16(frame);
    frame.push((crc >> 8) as u8);
    frame.push((crc & 0xFF) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        // crc16 over empty input == initial value (0x0000), byte-swapped == 0x0000.
        assert_eq!(crc16(&[]), 0x0000);
    }

    #[test]
    fn append_round_trip() {
        let mut buf = vec![0x01, 0x02, 0xAA, 0xBB];
        let expected = crc16(&buf);
        append_crc(&mut buf);
        let crc_on_wire = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
        assert_eq!(crc_on_wire, expected);
    }
}
