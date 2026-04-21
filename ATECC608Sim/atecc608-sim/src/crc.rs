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
