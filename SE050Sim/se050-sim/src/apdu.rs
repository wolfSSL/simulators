/* apdu.rs
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

/// APDU (Application Protocol Data Unit) parser and response builder.
/// Handles ISO 7816-4 command and response APDUs.

use crate::tlv::{self, Tlv};

#[derive(Debug)]
pub struct ParsedApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u16>,
}

impl ParsedApdu {
    /// Parse a raw APDU byte slice into a ParsedApdu.
    pub fn parse(raw: &[u8]) -> Result<Self, ApduError> {
        if raw.len() < 4 {
            return Err(ApduError::TooShort);
        }

        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];

        if raw.len() == 4 {
            // Case 1: no data, no Le
            return Ok(Self { cla, ins, p1, p2, data: vec![], le: None });
        }

        if raw.len() == 5 {
            // Case 2: Le only (short)
            return Ok(Self { cla, ins, p1, p2, data: vec![], le: Some(raw[4] as u16) });
        }

        // Check for extended length encoding
        if raw[4] == 0x00 && raw.len() >= 7 {
            // Extended Lc: 0x00 Lc_hi Lc_lo
            let lc = ((raw[5] as usize) << 8) | (raw[6] as usize);
            if lc == 0 {
                // Extended Le without Lc: 0x00 Le_hi Le_lo
                let le = ((raw[5] as u16) << 8) | (raw[6] as u16);
                return Ok(Self { cla, ins, p1, p2, data: vec![], le: Some(le) });
            }
            let data_end = 7 + lc;
            if data_end > raw.len() {
                return Err(ApduError::InvalidLength);
            }
            let data = raw[7..data_end].to_vec();
            let le = if data_end + 2 <= raw.len() {
                // Extended Le follows
                Some(((raw[data_end] as u16) << 8) | (raw[data_end + 1] as u16))
            } else if data_end + 1 == raw.len() {
                Some(raw[data_end] as u16)
            } else {
                None
            };
            return Ok(Self { cla, ins, p1, p2, data, le });
        }

        // Short Lc
        let lc = raw[4] as usize;
        let data_end = 5 + lc;
        if data_end > raw.len() {
            return Err(ApduError::InvalidLength);
        }
        let data = raw[5..data_end].to_vec();
        let le = if data_end < raw.len() {
            Some(raw[data_end] as u16)
        } else {
            None
        };

        Ok(Self { cla, ins, p1, p2, data, le })
    }

    /// Parse the TLVs in the data field.
    pub fn parse_tlvs(&self) -> Result<Vec<Tlv>, tlv::TlvError> {
        if self.data.is_empty() {
            return Ok(vec![]);
        }
        tlv::parse_tlvs(&self.data)
    }

    /// Get the base instruction (masked with 0x1F per AN12413 Table 17).
    pub fn base_ins(&self) -> u8 {
        self.ins & 0x1F
    }

    /// Get the credential type from P1 (bits 4:0).
    pub fn cred_type(&self) -> u8 {
        self.p1 & 0x1F
    }

    /// Get the key type from P1 (bits 6:5).
    pub fn key_type(&self) -> u8 {
        self.p1 & 0x60
    }
}

#[derive(Debug)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl ApduResponse {
    pub fn success() -> Self {
        Self { data: vec![], sw: 0x9000 }
    }

    pub fn success_with_data(data: Vec<u8>) -> Self {
        Self { data, sw: 0x9000 }
    }

    pub fn success_with_tlvs(tlvs: &[Tlv]) -> Self {
        Self {
            data: tlv::encode_tlvs(tlvs),
            sw: 0x9000,
        }
    }

    pub fn error(sw: u16) -> Self {
        Self { data: vec![], sw }
    }

    /// Serialize to bytes: data + SW1 + SW2
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        out.push((self.sw >> 8) as u8);
        out.push(self.sw as u8);
        out
    }
}

// Standard SE050 status words
pub const SW_NO_ERROR: u16 = 0x9000;
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
pub const SW_SECURITY_STATUS: u16 = 0x6982;
pub const SW_WRONG_DATA: u16 = 0x6A80;
pub const SW_DATA_INVALID: u16 = 0x6984;
pub const SW_COMMAND_NOT_ALLOWED: u16 = 0x6986;
pub const SW_WRONG_P1P2: u16 = 0x6A86;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const SW_FILE_NOT_FOUND: u16 = 0x6A82;

// SE050 instruction constants (masked with 0x1F)
pub const INS_WRITE: u8 = 0x01;
pub const INS_READ: u8 = 0x02;
pub const INS_CRYPTO: u8 = 0x03;
pub const INS_MGMT: u8 = 0x04;
pub const INS_PROCESS: u8 = 0x05;
pub const INS_IMPORT_EXTERNAL: u8 = 0x06;

// P1 credential types
pub const P1_DEFAULT: u8 = 0x00;
pub const P1_EC: u8 = 0x01;
pub const P1_RSA: u8 = 0x02;
pub const P1_AES: u8 = 0x03;
pub const P1_DES: u8 = 0x04;
pub const P1_HMAC: u8 = 0x05;
pub const P1_BINARY: u8 = 0x06;
pub const P1_USERID: u8 = 0x07;
pub const P1_COUNTER: u8 = 0x08;
pub const P1_PCR: u8 = 0x09;
pub const P1_CURVE: u8 = 0x0B;
pub const P1_SIGNATURE: u8 = 0x0C;
pub const P1_MAC: u8 = 0x0D;
pub const P1_CIPHER: u8 = 0x0E;
pub const P1_CRYPTO_OBJ: u8 = 0x10;

// P1 key type bits
pub const P1_KEY_PAIR: u8 = 0x60;
pub const P1_PRIVATE_KEY: u8 = 0x40;
pub const P1_PUBLIC_KEY: u8 = 0x20;

// P2 operation constants
pub const P2_DEFAULT: u8 = 0x00;
pub const P2_GENERATE: u8 = 0x03;
pub const P2_CREATE: u8 = 0x04;
pub const P2_SIZE: u8 = 0x07;
pub const P2_SIGN: u8 = 0x09;
pub const P2_VERIFY: u8 = 0x0A;
pub const P2_INIT: u8 = 0x0B;
pub const P2_UPDATE: u8 = 0x0C;
pub const P2_FINAL: u8 = 0x0D;
pub const P2_ONESHOT: u8 = 0x0E;
pub const P2_DH: u8 = 0x0F;
pub const P2_VERSION: u8 = 0x20;
pub const P2_MEMORY: u8 = 0x22;
pub const P2_LIST: u8 = 0x25;
pub const P2_TYPE: u8 = 0x26;
pub const P2_EXIST: u8 = 0x27;
pub const P2_DELETE_OBJECT: u8 = 0x28;
pub const P2_DELETE_ALL: u8 = 0x2A;
pub const P2_ID: u8 = 0x36;
pub const P2_ENCRYPT_ONESHOT: u8 = 0x37;
pub const P2_DECRYPT_ONESHOT: u8 = 0x38;
pub const P2_ENCRYPT_INIT: u8 = 0x42;
pub const P2_DECRYPT_INIT: u8 = 0x43;
pub const P2_CRYPTO_LIST: u8 = 0x47;
pub const P2_RAW: u8 = 0x4F;
pub const P2_RANDOM: u8 = 0x49;

// Secure object types (for ReadType responses)
pub const OBJ_TYPE_EC_KEY_PAIR: u8 = 0x01;
pub const OBJ_TYPE_EC_PUB_KEY: u8 = 0x03;
pub const OBJ_TYPE_AES_KEY: u8 = 0x09;
pub const OBJ_TYPE_BINARY_FILE: u8 = 0x0B;
pub const OBJ_TYPE_USERID: u8 = 0x0C;
pub const OBJ_TYPE_COUNTER: u8 = 0x0D;
pub const OBJ_TYPE_HMAC_KEY: u8 = 0x11;

#[derive(Debug)]
pub enum ApduError {
    TooShort,
    InvalidLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_select() {
        // SELECT APDU: CLA=0x00 INS=0xA4 P1=0x04 P2=0x00 Lc=0x10 data(16) Le=0x00
        let raw = [
            0x00, 0xA4, 0x04, 0x00, 0x10,
            0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
            0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let apdu = ParsedApdu::parse(&raw).unwrap();
        assert_eq!(apdu.cla, 0x00);
        assert_eq!(apdu.ins, 0xA4);
        assert_eq!(apdu.p1, 0x04);
        assert_eq!(apdu.p2, 0x00);
        assert_eq!(apdu.data.len(), 16);
        assert_eq!(apdu.le, Some(0));
    }

    #[test]
    fn test_parse_no_data() {
        // GetVersion: CLA=0x80 INS=0x84 P1=0x00 P2=0x20 Le=0x0B
        let raw = [0x80, 0x84, 0x00, 0x20, 0x0B];
        let apdu = ParsedApdu::parse(&raw).unwrap();
        assert_eq!(apdu.cla, 0x80);
        assert_eq!(apdu.ins, 0x84);
        assert_eq!(apdu.data.len(), 0);
        assert_eq!(apdu.le, Some(0x0B));
    }

    #[test]
    fn test_response_to_bytes() {
        let resp = ApduResponse::success_with_data(vec![0x01, 0x02, 0x03]);
        let bytes = resp.to_bytes();
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x90, 0x00]);
    }
}
