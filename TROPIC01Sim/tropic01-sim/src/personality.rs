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
//! A personality names one chip the simulator models. Each of its
//! behaviors comes from one of two sources:
//!
//! * the part ([`Part`]): silicon revision, bootloader and factory
//!   provisioning (CHIP_ID layout, pairing key in slot 0, firmware debug
//!   log);
//! * the firmware ([`Firmware`]): application and SPECT firmware versions,
//!   R-Memory slot size, how malformed L3 commands are treated, ...
//!
//! The simulator models three combinations:
//!
//! * `es-0.1.2` (default): an engineering-sample part (ABAB silicon,
//!   bootloader 1.0.1) running application FW 0.1.2 / SPECT FW 0.3.1, as
//!   shipped. Cross-checked against a real chip with the conformance probe
//!   described in `HARDWARE_VALIDATION.md`.
//! * `es-2.2.0`: the same engineering-sample part after libtropic's
//!   firmware update to application FW 2.2.0 / SPECT FW 1.3.0 and Tropic
//!   Square's fix for erratum OI_TR01_ERR_2026090100 (RNGTEST_DIS cleared in
//!   R-Config and I-Config). Cross-checked against the same chip after it
//!   was updated.
//! * `2.2.0`: a production part (ACAB silicon, bootloader 2.0.1) running
//!   application FW 2.2.0 / SPECT FW 1.3.0. It shares its firmware
//!   behaviors with `es-2.2.0`; its part behaviors follow Tropic Square's
//!   TROPIC01 functional model (ts-tvl) and libtropic's model
//!   configuration. Not bench-validated as a whole.

use serde::{Deserialize, Serialize};

use crate::object_store::{LT_SH0PUB_ENG_SAMPLE, LT_SH0PUB_PROD0};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Personality {
    #[default]
    #[serde(rename = "es-0.1.2")]
    Es012,
    #[serde(rename = "es-2.2.0")]
    Es220,
    #[serde(rename = "2.2.0")]
    Fw220,
}

/// Silicon, bootloader and factory provisioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// Engineering sample: ABAB silicon, bootloader 1.0.1, libtropic's
    /// engineering-sample pairing key, firmware debug log enabled.
    EngineeringSample,
    /// Production: ACAB silicon, bootloader 2.0.1, `prod0` pairing key,
    /// firmware debug log disabled.
    Production,
}

/// Application (RISC-V) and SPECT firmware release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Firmware {
    /// Application FW 0.1.2, SPECT FW 0.3.1.
    V0_1_2,
    /// Application FW 2.2.0, SPECT FW 1.3.0.
    V2_2_0,
}

impl Personality {
    pub const ALL: [Personality; 3] = [Personality::Es012, Personality::Es220, Personality::Fw220];

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "es-0.1.2" | "0.1.2" | "es" => Some(Personality::Es012),
            "es-2.2.0" => Some(Personality::Es220),
            "2.2.0" | "prod" | "prod-2.2.0" => Some(Personality::Fw220),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Personality::Es012 => "es-0.1.2",
            Personality::Es220 => "es-2.2.0",
            Personality::Fw220 => "2.2.0",
        }
    }

    pub fn part(self) -> Part {
        match self {
            Personality::Es012 | Personality::Es220 => Part::EngineeringSample,
            Personality::Fw220 => Part::Production,
        }
    }

    pub fn firmware(self) -> Firmware {
        match self {
            Personality::Es012 => Firmware::V0_1_2,
            Personality::Es220 | Personality::Fw220 => Firmware::V2_2_0,
        }
    }

    /// GET_INFO(RISCV_FW_VERSION) in Application mode: `[rfu, patch, minor,
    /// major]` as libtropic decodes it.
    pub fn riscv_fw_version(self) -> [u8; 4] {
        match self.firmware() {
            Firmware::V0_1_2 => [0x00, 0x02, 0x01, 0x00],
            Firmware::V2_2_0 => [0x00, 0x00, 0x02, 0x02],
        }
    }

    /// GET_INFO(SPECT_FW_VERSION) in Application mode.
    pub fn spect_fw_version(self) -> [u8; 4] {
        match self.firmware() {
            Firmware::V0_1_2 => [0x00, 0x01, 0x03, 0x00],
            Firmware::V2_2_0 => [0x00, 0x00, 0x03, 0x01],
        }
    }

    /// Sizes of the application and SPECT firmware images, as the bank
    /// headers report them (taken from the bench chip's banks).
    pub fn fw_image_sizes(self) -> (u32, u32) {
        match self.firmware() {
            Firmware::V0_1_2 => (0x5ec0, 0x2350),
            Firmware::V2_2_0 => (0x5374, 0x2920),
        }
    }

    /// Whether the second firmware bank pair holds a copy of the running
    /// firmware. libtropic's `lt_do_mutable_fw_update` writes both bank
    /// pairs, so a part updated in the field has both filled.
    pub fn fw_bank2_written(self) -> bool {
        self == Personality::Es220
    }

    /// GET_INFO(RISCV_FW_VERSION) in Maintenance (start-up) mode reports the
    /// bootloader version with bit 7 of the major byte set.
    pub fn bootloader_version(self) -> [u8; 4] {
        match self.part() {
            Part::EngineeringSample => [0x00, 0x01, 0x00, 0x81],
            Part::Production => [0x00, 0x01, 0x00, 0x82],
        }
    }

    /// GET_INFO(SPECT_FW_VERSION) in Maintenance mode.
    pub fn bootloader_spect_version(self) -> [u8; 4] {
        [0x00, 0x00, 0x00, 0x80]
    }

    /// Size of a GET_INFO(FW_BANK) header: bootloader 1.x uses 20 bytes,
    /// bootloader 2.x 52 bytes.
    pub fn fw_bank_header_len(self) -> usize {
        match self.part() {
            Part::EngineeringSample => 20,
            Part::Production => 52,
        }
    }

    /// Largest R-Memory user data slot (444 B before application FW 2.0.0,
    /// 475 B from 2.0.0 on).
    pub fn r_mem_slot_max(self) -> usize {
        match self.firmware() {
            Firmware::V0_1_2 => 444,
            Firmware::V2_2_0 => 475,
        }
    }

    /// FW 2.x rejects an L3 command whose size does not match its command
    /// ID with an L2 GEN_ERR and closes the session (observed on FW 2.2.0,
    /// FW 2.0.0 notes). FW 0.1.2 is lenient and handles each command
    /// differently, see `handlers::l3`.
    pub fn strict_l3_sizes(self) -> bool {
        self.firmware() == Firmware::V2_2_0
    }

    /// While FW 2.x processes a request it keeps READY set in CHIP_STATUS
    /// and answers a poll with STATUS NO_RESP, like an idle poll. FW 0.1.2
    /// (and the bootloader) clear READY instead.
    pub fn busy_poll_ready(self) -> bool {
        self.firmware() == Firmware::V2_2_0
    }

    /// On FW 0.1.2 a Handshake_Req naming a pairing slot above 3 puts the
    /// chip into Alarm Mode (observed on hardware). FW 2.x answers HSK_ERR
    /// (ts-tvl; not tried on the bench chip).
    pub fn bad_pairing_index_alarms(self) -> bool {
        self.firmware() == Firmware::V0_1_2
    }

    /// FW 0.1.2 answers EDDSA_Sign with an empty message with RESULT_OK and
    /// no signature; FW 2.2.0 signs the empty message.
    pub fn eddsa_empty_message_unsigned(self) -> bool {
        self.firmware() == Firmware::V0_1_2
    }

    /// Get_Log_Req: engineering samples have the FW debug log enabled and
    /// always return a full 252-byte chunk; production parts have it
    /// irreversibly disabled and return an empty log.
    pub fn fw_log(self) -> Vec<u8> {
        match self.part() {
            Part::EngineeringSample => {
                let mut log = b"TROPIC01Sim: firmware debug log is not modelled\n".to_vec();
                log.resize(252, 0);
                log
            }
            Part::Production => Vec::new(),
        }
    }

    /// Host pairing key pre-provisioned into pairing slot 0: the libtropic
    /// engineering-sample key on ES parts, the `prod0` key on production
    /// parts.
    pub fn default_sh0_pub(self) -> [u8; 32] {
        match self.part() {
            Part::EngineeringSample => LT_SH0PUB_ENG_SAMPLE,
            Part::Production => LT_SH0PUB_PROD0,
        }
    }

    /// R-Config CFG_START_UP as read back from the bench chip: bit 4 cleared
    /// as shipped, and bit 2 (RNGTEST_DIS) cleared too after the erratum
    /// fix. Production defaults are not public, so FW 2.2.0 starts fully
    /// erased.
    pub fn default_r_config_start_up(self) -> u32 {
        match self {
            Personality::Es012 => 0xffff_ffef,
            Personality::Es220 => 0xffff_ffeb,
            Personality::Fw220 => 0xffff_ffff,
        }
    }

    /// I-Config CFG_START_UP: erased, except for RNGTEST_DIS cleared by the
    /// erratum fix on the `es-2.2.0` chip.
    pub fn default_i_config_start_up(self) -> u32 {
        match self {
            Personality::Es220 => 0xffff_fffb,
            Personality::Es012 | Personality::Fw220 => 0xffff_ffff,
        }
    }

    /// CHIP_ID object (128 bytes). Layout follows `struct lt_chip_id_t`. The
    /// ES layout is the bench chip's (CHIP_ID v0.0.0.1, which has no
    /// silicon revision); the production layout follows libtropic's model
    /// configuration (v1.0.0.0, ACAB silicon, QFN32, EPS Brno fab). The
    /// serial number fields are randomized per simulated device.
    pub fn chip_id(self, serial: &[u8; 8]) -> Vec<u8> {
        let mut id = vec![0u8; 128];
        match self.part() {
            Part::EngineeringSample => {
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
            Part::Production => {
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
        for p in Personality::ALL {
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

    #[test]
    fn updated_es_part_keeps_part_and_takes_firmware() {
        let p = Personality::Es220;
        assert_eq!(p.part(), Personality::Es012.part());
        assert_eq!(p.firmware(), Personality::Fw220.firmware());
        assert_eq!(
            p.bootloader_version(),
            Personality::Es012.bootloader_version()
        );
        assert_eq!(p.fw_bank_header_len(), 20);
        assert_eq!(p.default_sh0_pub(), LT_SH0PUB_ENG_SAMPLE);
        assert_eq!(p.fw_log().len(), 252);
        assert_eq!(p.chip_id(&[0; 8]), Personality::Es012.chip_id(&[0; 8]));
        assert_eq!(p.riscv_fw_version(), Personality::Fw220.riscv_fw_version());
        assert_eq!(p.r_mem_slot_max(), 475);
        assert!(p.strict_l3_sizes());
        // Erratum OI_TR01_ERR_2026090100 fix: RNGTEST_DIS (bit 2) cleared
        assert_eq!(p.default_r_config_start_up() & 0x4, 0);
        assert_eq!(p.default_i_config_start_up() & 0x4, 0);
    }
}
