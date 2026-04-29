/* t1.rs
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

/// T=1 protocol responder (ISO 7816-3 over I2C).
/// This is the SE050-side of the T=1 protocol, mirroring the driver's T1overI2C.

use crate::apdu::{ApduResponse, ParsedApdu};
use crate::dispatch;
use crate::object_store::ObjectStore;

/// CRC-16/X-25 calculation using the crc16 crate (matches the driver).
pub fn crc16_x25(data: &[u8]) -> u16 {
    crc16::State::<crc16::X_25>::calculate(data)
}

// T=1 PCB byte encoding
const T1_S_REQUEST: u8 = 0xC0;
const T1_S_RESPONSE: u8 = 0xE0;
const T1_S_INTERFACE_SOFT_RESET: u8 = 0x0F;
const T1_R_CODE_MASK: u8 = 0xEC;
const T1_R_CODE: u8 = 0x80;

/// ATR data matching the test expectations from the nxp-se050 driver.
/// 35 bytes: protocol_version(1) + vendor_id(5) + dllp_hdr(1) + dllp(4) +
///           plp_type(1) + plp_len(1) + plp_data(11) + hb_len(1) + historical_bytes(10)
const ATR_DATA: [u8; 35] = [
    0x00,                               // protocol version
    0xA0, 0x00, 0x00, 0x03, 0x96,       // vendor ID (NXP)
    0x04,                               // DLLP length
    0x03, 0xE8,                         // BWT = 1000ms
    0x00, 0xFE,                         // IFSC = 254
    0x02,                               // PLP type = I2C
    0x0B,                               // PLP length = 11
    0x03, 0xE8,                         // MCF = 1000
    0x08,                               // configuration
    0x01,                               // MPOT = 1ms
    0x00, 0x00, 0x00,                   // RFU
    0x00, 0x64,                         // SEGT = 100us
    0x00, 0x00,                         // WUT = 0
    0x0A,                               // historical bytes length = 10
    0x4A, 0x43, 0x4F, 0x50, 0x34, 0x20, // "JCOP4 "
    0x41, 0x54, 0x50, 0x4F,             // "ATPO"
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum FrameType {
    IFrame { seq: u8, multi: bool },
    RFrame { seq: u8, err: u8 },
    SFrame { code: u8, is_response: bool },
}

fn parse_pcb(pcb: u8) -> Option<FrameType> {
    if (pcb & T1_R_CODE_MASK) == T1_R_CODE {
        Some(FrameType::RFrame {
            seq: (pcb & 0x10) >> 4,
            err: pcb & 0x03,
        })
    } else if (pcb & T1_S_REQUEST) == T1_S_REQUEST {
        let code = pcb & !T1_S_RESPONSE;
        let is_response = (pcb & 0x20) != 0;
        Some(FrameType::SFrame { code, is_response })
    } else if (pcb & 0x9F) == 0 {
        Some(FrameType::IFrame {
            seq: (pcb & 0x40) >> 6,
            multi: (pcb & 0x20) != 0,
        })
    } else {
        None
    }
}

fn encode_pcb(ft: FrameType) -> u8 {
    match ft {
        FrameType::IFrame { seq, multi } => {
            (seq << 6) | if multi { 0x20 } else { 0 }
        }
        FrameType::RFrame { seq, err } => {
            T1_R_CODE | (seq << 4) | err
        }
        FrameType::SFrame { code, is_response } => {
            (if is_response { T1_S_RESPONSE } else { T1_S_REQUEST }) | code
        }
    }
}

/// Parsed T=1 frame from I2C write data.
struct T1Frame {
    #[allow(dead_code)]
    nad: u8,
    frame_type: FrameType,
    payload: Vec<u8>,
}

fn parse_frame(data: &[u8]) -> Option<T1Frame> {
    if data.len() < 5 {
        return None; // NAD + PCB + LEN + CRC(2) minimum
    }
    let nad = data[0];
    let pcb = data[1];
    let len = data[2] as usize;

    if data.len() < 3 + len + 2 {
        return None;
    }

    // Verify CRC
    let crc_data = &data[..3 + len];
    let expected_crc = crc16_x25(crc_data);
    let received_crc = (data[3 + len] as u16) | ((data[3 + len + 1] as u16) << 8);
    if expected_crc != received_crc {
        return None;
    }

    let frame_type = parse_pcb(pcb)?;
    let payload = data[3..3 + len].to_vec();

    Some(T1Frame { nad, frame_type, payload })
}

/// Build a T=1 frame as raw bytes, returning (header_chunk, payload_crc_chunk).
/// The driver reads frames in two phases: 3-byte header, then LEN+2 bytes payload+CRC.
fn build_frame(nad: u8, ft: FrameType, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pcb = encode_pcb(ft);
    let header = vec![nad, pcb, payload.len() as u8];

    // CRC covers header + payload
    let mut crc_input = header.clone();
    crc_input.extend_from_slice(payload);
    let crc = crc16_x25(&crc_input);

    let mut payload_crc = Vec::with_capacity(payload.len() + 2);
    payload_crc.extend_from_slice(payload);
    payload_crc.push(crc as u8);        // CRC low byte (little-endian)
    payload_crc.push((crc >> 8) as u8); // CRC high byte

    (header, payload_crc)
}

/// T=1 protocol state machine for the simulator side.
pub struct T1Responder {
    nad_se2hd: u8,
    iseq_rcv: u8,   // expected I-frame seq from host
    iseq_snd: u8,   // our I-frame send seq
    apdu_reassembly: Vec<u8>,
}

impl T1Responder {
    pub fn new(nad_hd2se: u8) -> Self {
        // Reverse the NAD nibbles to get SE-to-host NAD
        let nad_se2hd = ((nad_hd2se & 0xF0) >> 4) | ((nad_hd2se & 0x0F) << 4);
        Self {
            nad_se2hd,
            iseq_rcv: 0,
            iseq_snd: 0,
            apdu_reassembly: Vec::new(),
        }
    }

    /// Process a T=1 frame received from the host (via I2C write).
    /// Returns response chunks to queue for I2C reads (header, payload+crc pairs).
    pub fn process_frame(
        &mut self,
        data: &[u8],
        store: &mut ObjectStore,
    ) -> Vec<Vec<u8>> {
        let frame = match parse_frame(data) {
            Some(f) => f,
            None => {
                log::warn!("Failed to parse T=1 frame");
                return vec![];
            }
        };

        match frame.frame_type {
            FrameType::SFrame { code, is_response: false } => {
                self.handle_s_request(code)
            }
            FrameType::IFrame { seq, multi } => {
                self.handle_i_frame(seq, multi, &frame.payload, store)
            }
            FrameType::RFrame { .. } => {
                // R-frames during multi-frame response sending
                // Currently we pre-queue all response frames, so we just ignore R-frames
                vec![]
            }
            _ => vec![],
        }
    }

    fn handle_s_request(&mut self, code: u8) -> Vec<Vec<u8>> {
        match code {
            T1_S_INTERFACE_SOFT_RESET => {
                // Reset sequence numbers and respond with ATR
                self.iseq_rcv = 0;
                self.iseq_snd = 0;
                self.apdu_reassembly.clear();

                let ft = FrameType::SFrame {
                    code: T1_S_INTERFACE_SOFT_RESET,
                    is_response: true,
                };
                let (header, payload_crc) = build_frame(self.nad_se2hd, ft, &ATR_DATA);
                vec![header, payload_crc]
            }
            0x00 => {
                // Resync: reset sequence numbers, respond with empty S-response
                self.iseq_rcv = 0;
                self.iseq_snd = 0;
                self.apdu_reassembly.clear();

                let ft = FrameType::SFrame { code: 0x00, is_response: true };
                let (header, payload_crc) = build_frame(self.nad_se2hd, ft, &[]);
                vec![header, payload_crc]
            }
            0x07 => {
                // GetATR: respond with ATR data (same as InterfaceSoftReset but no state reset)
                let ft = FrameType::SFrame { code: 0x07, is_response: true };
                let (header, payload_crc) = build_frame(self.nad_se2hd, ft, &ATR_DATA);
                vec![header, payload_crc]
            }
            _ => {
                // Other S-frames: respond with matching S-response, empty payload
                let ft = FrameType::SFrame { code, is_response: true };
                let (header, payload_crc) = build_frame(self.nad_se2hd, ft, &[]);
                vec![header, payload_crc]
            }
        }
    }

    fn handle_i_frame(
        &mut self,
        seq: u8,
        multi: bool,
        payload: &[u8],
        store: &mut ObjectStore,
    ) -> Vec<Vec<u8>> {
        // Check sequence number
        if seq != self.iseq_rcv {
            log::warn!("Sequence mismatch: expected {}, got {}", self.iseq_rcv, seq);
        }
        self.iseq_rcv ^= 1;

        self.apdu_reassembly.extend_from_slice(payload);

        if multi {
            // More frames coming - send R-frame ACK
            let ft = FrameType::RFrame { seq: self.iseq_rcv, err: 0 };
            let (header, payload_crc) = build_frame(self.nad_se2hd, ft, &[]);
            return vec![header, payload_crc];
        }

        // Complete APDU received - process it
        let apdu_bytes = std::mem::take(&mut self.apdu_reassembly);
        let response = self.process_apdu(&apdu_bytes, store);
        let response_bytes = response.to_bytes();

        // Build response I-frame(s)
        self.build_response_frames(&response_bytes)
    }

    fn process_apdu(&self, apdu_bytes: &[u8], store: &mut ObjectStore) -> ApduResponse {
        match ParsedApdu::parse(apdu_bytes) {
            Ok(apdu) => dispatch::dispatch(&apdu, store),
            Err(e) => {
                log::warn!("Failed to parse APDU: {:?}", e);
                ApduResponse::error(0x6700) // Wrong length
            }
        }
    }

    fn build_response_frames(&mut self, response_bytes: &[u8]) -> Vec<Vec<u8>> {
        let max_payload = 254; // MAX_IFSC
        let mut chunks = Vec::new();

        if response_bytes.len() <= max_payload {
            // Single frame response
            let ft = FrameType::IFrame {
                seq: self.iseq_snd,
                multi: false,
            };
            self.iseq_snd ^= 1;
            let (header, payload_crc) = build_frame(self.nad_se2hd, ft, response_bytes);
            chunks.push(header);
            chunks.push(payload_crc);
        } else {
            // Multi-frame response
            let mut offset = 0;
            while offset < response_bytes.len() {
                let remaining = response_bytes.len() - offset;
                let chunk_len = remaining.min(max_payload);
                let is_last = offset + chunk_len >= response_bytes.len();

                let ft = FrameType::IFrame {
                    seq: self.iseq_snd,
                    multi: !is_last,
                };
                self.iseq_snd ^= 1;

                let (header, payload_crc) =
                    build_frame(self.nad_se2hd, ft, &response_bytes[offset..offset + chunk_len]);
                chunks.push(header);
                chunks.push(payload_crc);

                offset += chunk_len;
            }
        }

        chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16() {
        // From driver test: assert_eq!(0x78a1, Se050CRC::calculate(&[0,48,95,111,242]));
        assert_eq!(0x78a1, crc16_x25(&[0, 48, 95, 111, 242]));
    }

    #[test]
    fn test_parse_s_frame() {
        // InterfaceSoftReset request: [0x5a, 0xcf, 0x00, 0x37, 0x7f]
        let frame = parse_frame(&[0x5a, 0xcf, 0x00, 0x37, 0x7f]).unwrap();
        assert_eq!(frame.nad, 0x5a);
        assert!(matches!(
            frame.frame_type,
            FrameType::SFrame { code: 0x0F, is_response: false }
        ));
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn test_build_atr_response() {
        let (header, payload_crc) = build_frame(
            0xA5,
            FrameType::SFrame { code: T1_S_INTERFACE_SOFT_RESET, is_response: true },
            &ATR_DATA,
        );
        assert_eq!(header, vec![0xA5, 0xEF, 0x23]);
        assert_eq!(payload_crc.len(), 35 + 2); // ATR + CRC
        // Verify CRC matches the test constant
        assert_eq!(&payload_crc[..35], &ATR_DATA);
        assert_eq!(payload_crc[35], 0x87);
        assert_eq!(payload_crc[36], 0x77);
    }
}
