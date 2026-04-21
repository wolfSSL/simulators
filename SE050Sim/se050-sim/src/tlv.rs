/* tlv.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// TLV (Tag-Length-Value) encoder/decoder matching the SE050 SimpleTlv format.

#[derive(Debug, Clone)]
pub struct Tlv {
    pub tag: u8,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(tag: u8, value: &[u8]) -> Self {
        Self {
            tag,
            value: value.to_vec(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.tag);
        if self.value.len() < 128 {
            out.push(self.value.len() as u8);
        } else {
            out.push(0x82);
            out.push((self.value.len() >> 8) as u8);
            out.push(self.value.len() as u8);
        }
        out.extend_from_slice(&self.value);
        out
    }
}

/// Parse a sequence of TLVs from a byte slice.
pub fn parse_tlvs(data: &[u8]) -> Result<Vec<Tlv>, TlvError> {
    let mut result = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        if offset + 1 >= data.len() {
            return Err(TlvError::TooShort);
        }
        let tag = data[offset];
        let (len, header_size) = if data[offset + 1] == 0x82 {
            if offset + 4 > data.len() {
                return Err(TlvError::TooShort);
            }
            let len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
            (len, 4)
        } else if data[offset + 1] < 0x80 {
            (data[offset + 1] as usize, 2)
        } else {
            return Err(TlvError::InvalidLength);
        };

        if offset + header_size + len > data.len() {
            return Err(TlvError::TooShort);
        }
        let value = data[offset + header_size..offset + header_size + len].to_vec();
        result.push(Tlv { tag, value });
        offset += header_size + len;
    }

    Ok(result)
}

/// Encode a slice of TLVs into a byte vector.
pub fn encode_tlvs(tlvs: &[Tlv]) -> Vec<u8> {
    let mut out = Vec::new();
    for tlv in tlvs {
        out.extend_from_slice(&tlv.encode());
    }
    out
}

/// Find the first TLV with the given tag in a list.
pub fn find_tlv(tlvs: &[Tlv], tag: u8) -> Option<&Tlv> {
    tlvs.iter().find(|t| t.tag == tag)
}

/// Find all TLVs with the given tag in a list.
pub fn find_tlvs(tlvs: &[Tlv], tag: u8) -> Vec<&Tlv> {
    tlvs.iter().filter(|t| t.tag == tag).collect()
}

#[derive(Debug)]
pub enum TlvError {
    TooShort,
    InvalidLength,
}

// SE050 TLV tag constants (from AN12413 Table 27)
pub const TAG_SESSION_ID: u8 = 0x10;
pub const TAG_POLICY: u8 = 0x11;
pub const TAG_MAX_ATTEMPTS: u8 = 0x12;
pub const TAG_1: u8 = 0x41;
pub const TAG_2: u8 = 0x42;
pub const TAG_3: u8 = 0x43;
pub const TAG_4: u8 = 0x44;
pub const TAG_5: u8 = 0x45;
pub const TAG_6: u8 = 0x46;
pub const TAG_7: u8 = 0x47;
pub const TAG_8: u8 = 0x48;
pub const TAG_9: u8 = 0x49;
pub const TAG_10: u8 = 0x4a;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_short() {
        let tlv = Tlv::new(TAG_1, &[0x01, 0x02, 0x03]);
        assert_eq!(tlv.encode(), vec![0x41, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_long() {
        let data = vec![0xAA; 200];
        let tlv = Tlv::new(TAG_1, &data);
        let encoded = tlv.encode();
        assert_eq!(encoded[0], 0x41);
        assert_eq!(encoded[1], 0x82);
        assert_eq!(encoded[2], 0x00);
        assert_eq!(encoded[3], 200);
        assert_eq!(&encoded[4..], data.as_slice());
    }

    #[test]
    fn test_roundtrip() {
        let tlvs = vec![
            Tlv::new(TAG_1, &[0x01, 0x02]),
            Tlv::new(TAG_2, &[0x03]),
        ];
        let encoded = encode_tlvs(&tlvs);
        let parsed = parse_tlvs(&encoded).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].tag, TAG_1);
        assert_eq!(parsed[0].value, vec![0x01, 0x02]);
        assert_eq!(parsed[1].tag, TAG_2);
        assert_eq!(parsed[1].value, vec![0x03]);
    }
}
