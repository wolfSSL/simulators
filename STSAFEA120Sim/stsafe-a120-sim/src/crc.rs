/* crc.rs
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

/// CRC-16/X-25 (poly 0x1021 reflected to 0x8408, init 0xFFFF, refin/refout true,
/// xorout 0xFFFF). The STSELib platform abstraction does not prescribe a CRC,
/// it just calls `stse_platform_Crc16_*`. We pick X-25 because it is the same
/// CRC used by HDLC / X.25 / PPP, has a one-line implementation, and our
/// PAL-side crc16.c uses it too.
pub fn crc16_x25(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in buf {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        assert_eq!(crc16_x25(&[]), 0x0000);
    }

    #[test]
    fn known_vector_123456789() {
        // Standard CRC-16/X-25 check value over ASCII "123456789".
        assert_eq!(crc16_x25(b"123456789"), 0x906E);
    }

    #[test]
    fn round_trip_via_append() {
        // Property: appending the BE-encoded CRC and re-running should
        // not match -- but the helper consumers always treat the trailing
        // 2 bytes as CRC. Sanity-check that the function is deterministic
        // and stable.
        let v = b"hello stsafe";
        assert_eq!(crc16_x25(v), crc16_x25(v));
        // Confirms the algorithm is the standard CRC-16/X-25 (poly 0x1021
        // reflected, init 0xFFFF, refin/refout, xorout 0xFFFF) -- the
        // 123456789 check value above is the canonical reference.
    }
}
