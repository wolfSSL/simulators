/* personality.rs
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

//! Firmware personalities.
//!
//! TROPIC01 behavior differs between firmware releases in a handful of
//! places (identity blobs, the R-Memory slot size, how malformed L3
//! commands are treated, ...). The simulator models two of them:
//!
//! * `es-0.1.2` (default): an engineering-sample part running application
//!   FW 0.1.2 / SPECT FW 0.3.1 on bootloader 1.0.1 (ABAB silicon). Every
//!   behavior of this personality was cross-checked against a real chip
//!   with the conformance probe described in `HARDWARE_VALIDATION.md`.
//! * `2.2.0`: a production part (ACAB silicon, bootloader 2.0.1) running
//!   application FW 2.2.0 / SPECT FW 1.3.0, following Tropic Square's
//!   TROPIC01 functional model (ts-tvl) where it differs from the ES part.
//!   Not bench-validated.

use serde::{Deserialize, Serialize};

use crate::object_store::{LT_SH0PUB_ENG_SAMPLE, LT_SH0PUB_PROD0};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Personality {
    #[default]
    #[serde(rename = "es-0.1.2")]
    Es012,
    #[serde(rename = "2.2.0")]
    Fw220,
}

impl Personality {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "es-0.1.2" | "0.1.2" | "es" => Some(Personality::Es012),
            "2.2.0" | "prod" => Some(Personality::Fw220),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Personality::Es012 => "es-0.1.2",
            Personality::Fw220 => "2.2.0",
        }
    }

    /// GET_INFO(RISCV_FW_VERSION) in Application mode: `[rfu, patch, minor,
    /// major]` as libtropic decodes it.
    pub fn riscv_fw_version(self) -> [u8; 4] {
        match self {
            Personality::Es012 => [0x00, 0x02, 0x01, 0x00],
            Personality::Fw220 => [0x00, 0x00, 0x02, 0x02],
        }
    }

    /// GET_INFO(SPECT_FW_VERSION) in Application mode.
    pub fn spect_fw_version(self) -> [u8; 4] {
        match self {
            Personality::Es012 => [0x00, 0x01, 0x03, 0x00],
            Personality::Fw220 => [0x00, 0x00, 0x03, 0x01],
        }
    }

    /// GET_INFO(RISCV_FW_VERSION) in Maintenance (start-up) mode reports the
    /// bootloader version with bit 7 of the major byte set.
    pub fn bootloader_version(self) -> [u8; 4] {
        match self {
            Personality::Es012 => [0x00, 0x01, 0x00, 0x81],
            Personality::Fw220 => [0x00, 0x01, 0x00, 0x82],
        }
    }

    /// GET_INFO(SPECT_FW_VERSION) in Maintenance mode.
    pub fn bootloader_spect_version(self) -> [u8; 4] {
        [0x00, 0x00, 0x00, 0x80]
    }

    /// Size of a GET_INFO(FW_BANK) header: bootloader 1.x uses 20 bytes,
    /// bootloader 2.x 52 bytes.
    pub fn fw_bank_header_len(self) -> usize {
        match self {
            Personality::Es012 => 20,
            Personality::Fw220 => 52,
        }
    }

    /// Largest R-Memory user data slot (444 B before application FW 2.0.0,
    /// 475 B from 2.0.0 on).
    pub fn r_mem_slot_max(self) -> usize {
        match self {
            Personality::Es012 => 444,
            Personality::Fw220 => 475,
        }
    }

    /// FW 2.x rejects an L3 command whose size does not match its command
    /// ID with an L2 GEN_ERR and closes the session (ts-tvl, FW 2.0.0
    /// notes). FW 0.1.2 is lenient and handles each command differently,
    /// see `handlers::l3`.
    pub fn strict_l3_sizes(self) -> bool {
        self == Personality::Fw220
    }

    /// On FW 0.1.2 a Handshake_Req naming a pairing slot above 3 puts the
    /// chip into Alarm Mode (observed on hardware). FW 2.x answers HSK_ERR.
    pub fn bad_pairing_index_alarms(self) -> bool {
        self == Personality::Es012
    }

    /// The ES part answers EDDSA_Sign with an empty message with RESULT_OK
    /// and no signature.
    pub fn eddsa_empty_message_unsigned(self) -> bool {
        self == Personality::Es012
    }

    /// Get_Log_Req: the ES part has the FW debug log enabled and always
    /// returns a full 252-byte chunk; production parts have it
    /// irreversibly disabled and return an empty log.
    pub fn fw_log(self) -> Vec<u8> {
        match self {
            Personality::Es012 => {
                let mut log = b"TROPIC01Sim: firmware debug log is not modelled\n".to_vec();
                log.resize(252, 0);
                log
            }
            Personality::Fw220 => Vec::new(),
        }
    }

    /// Host pairing key pre-provisioned into pairing slot 0: the libtropic
    /// engineering-sample key on ES parts, the `prod0` key on production
    /// parts.
    pub fn default_sh0_pub(self) -> [u8; 32] {
        match self {
            Personality::Es012 => LT_SH0PUB_ENG_SAMPLE,
            Personality::Fw220 => LT_SH0PUB_PROD0,
        }
    }

    /// R-Config as read back from the bench chip. CFG_START_UP has bit 4
    /// cleared; everything else is erased. Production defaults are not
    /// public, so FW 2.2.0 starts fully erased.
    pub fn default_r_config_start_up(self) -> u32 {
        match self {
            Personality::Es012 => 0xffff_ffef,
            Personality::Fw220 => 0xffff_ffff,
        }
    }

    /// CHIP_ID object (128 bytes). Layout follows `struct lt_chip_id_t`. The
    /// ES layout is the bench chip's (CHIP_ID v0.0.0.1, which has no
    /// silicon revision); the production layout follows libtropic's model
    /// configuration (v1.0.0.0, ACAB silicon, QFN32, EPS Brno fab). The
    /// serial number fields are randomized per simulated device.
    pub fn chip_id(self, serial: &[u8; 8]) -> Vec<u8> {
        let mut id = vec![0u8; 128];
        match self {
            Personality::Es012 => {
                id[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                // packg_type_id/rfu_1 zero; prov_ver_fab_id_pn
                id[36..40].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
                id[40..42].copy_from_slice(&[0x05, 0x44]);
                id[46..52].copy_from_slice(&[0xff; 6]);
                // ser_num: sn, fab_data (Tropic Square lab), fab_date,
                // lot_id, wafer_id, x, y
                id[52] = 0x01;
                id[53..56].copy_from_slice(&[0xf0, 0x0f, 0x00]);
                id[56..58].copy_from_slice(&[0x05, 0x44]);
                id[58..63].copy_from_slice(b"SIM01");
                id[63] = serial[0];
                id[64..66].copy_from_slice(&[serial[1], serial[2]]);
                id[66..68].copy_from_slice(&[serial[3], serial[4]]);
                // part number: length-prefixed "TROPIC01-ES"
                id[68] = 0x0b;
                id[69..80].copy_from_slice(b"TROPIC01-ES");
                id[80..84].copy_from_slice(&[0xff; 4]);
                id[84..104].copy_from_slice(&[
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ]);
                for b in id[104..124].iter_mut() {
                    *b = 0xff;
                }
                id[124..128].copy_from_slice(&[0x01, 0x03, 0x03, 0x00]);
            }
            Personality::Fw220 => {
                id[0..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
                id[28..32].copy_from_slice(b"ACAB");
                id[32..36].copy_from_slice(&[0x80, 0xaa, 0xff, 0xff]);
                id[36..40].copy_from_slice(&[0x01, 0xf0, 0x02, 0x00]);
                id[50..52].copy_from_slice(&[0xff, 0xff]);
                id[52] = 0x02;
                id[53..56].copy_from_slice(&[0xf0, 0x02, 0x00]);
                id[56..58].copy_from_slice(&[0x00, 0x00]);
                id[58..63].copy_from_slice(&[0x19, 0x06, 0x1b, 0x09, 0x33]);
                id[63] = serial[0];
                id[64..66].copy_from_slice(&[serial[1], serial[2]]);
                id[66..68].copy_from_slice(&[serial[3], serial[4]]);
                id[68] = 0x0d;
                id[69..82].copy_from_slice(b"TR01-C2S-T200");
                id[82..84].copy_from_slice(&[0xff, 0xff]);
                id[84..86].copy_from_slice(&[0x01, 0x04]);
                id[86..91].copy_from_slice(&[serial[5], serial[6], serial[7], 0x28, 0x00]);
                for b in id[96..128].iter_mut() {
                    *b = 0xff;
                }
            }
        }
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for p in [Personality::Es012, Personality::Fw220] {
            assert_eq!(Personality::from_name(p.name()), Some(p));
        }
        assert_eq!(Personality::from_name("bogus"), None);
    }

    #[test]
    fn es_chip_id_names_part() {
        let id = Personality::Es012.chip_id(&[0; 8]);
        assert_eq!(id.len(), 128);
        assert_eq!(&id[69..80], b"TROPIC01-ES");
    }
}
