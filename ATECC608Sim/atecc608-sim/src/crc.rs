/* crc.rs
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

/// CRC-16 as used by the ATECC608A / cryptoauthlib.
///
/// Polynomial 0x8005, initial value 0x0000, no input or output reflection.
/// This matches `atCRC()` in `cryptoauthlib/lib/calib/calib_basic.c`.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        for bit in 0..8 {
            let data_bit = ((byte >> bit) & 1) as u16;
            let crc_bit = crc >> 15;
            crc <<= 1;
            if data_bit != crc_bit {
                crc ^= 0x8005;
            }
        }
    }
    crc
}

/// Return the CRC as a `[lsb, msb]` pair, matching the on-wire order.
pub fn crc16_le(data: &[u8]) -> [u8; 2] {
    let c = crc16(data);
    [(c & 0xFF) as u8, (c >> 8) as u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Info command (opcode 0x30, P1/P2 zero) with count=0x07: the minimum
    /// command packet. Known golden CRC from Microchip sample captures.
    #[test]
    fn info_command_crc() {
        let pkt = [0x07, 0x30, 0x00, 0x00, 0x00];
        assert_eq!(crc16_le(&pkt), [0x03, 0x5D]);
    }

    /// Random command (opcode 0x1B, P1=0, P2=0x0000) with count=0x07.
    #[test]
    fn random_command_crc() {
        let pkt = [0x07, 0x1B, 0x00, 0x00, 0x00];
        let c = crc16_le(&pkt);
        // Sanity: should be deterministic and non-zero
        assert_ne!(c, [0, 0]);
        // Re-running must give the same value
        assert_eq!(crc16_le(&pkt), c);
    }

    #[test]
    fn empty_input_crc_is_zero() {
        assert_eq!(crc16(&[]), 0);
    }

    #[test]
    fn crc_round_trip_via_u16_and_bytes() {
        let pkt = [0x07u8, 0x30, 0x00, 0x00, 0x00];
        let u = crc16(&pkt);
        let b = crc16_le(&pkt);
        assert_eq!(u16::from_le_bytes(b), u);
    }
}
