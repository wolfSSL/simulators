/* mod.rs
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

//! SCP03 (GlobalPlatform Secure Channel Protocol 03, as used by NXP Platform
//! SCP) session state machine: the INITIALIZE UPDATE / EXTERNAL AUTHENTICATE
//! handshake and C-MAC / C-DEC / R-MAC / R-ENC wrapping of subsequent APDUs.
//!
//! The command-counter and ICV semantics mirror the NXP Plug & Trust host
//! stack (hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c, v04.07.01) exactly,
//! because host and card derive keystreams independently and must agree: the
//! counter is 1 after EXTERNAL AUTHENTICATE and the command ICV is
//! AES-ECB(S-ENC, counter).
//!
//! The counter-advance and response-ICV rules depend on the applet
//! generation, because the middleware tags the session differently either
//! side of applet 4.3 (see `Session::legacy`). Getting this wrong is silent:
//! the R-MAC still verifies, but the response decrypts to garbage and the
//! host reports "RAPDU Decoding failed No Padding found".

pub mod crypto;
pub mod keys;

use crate::apdu::{
    ApduResponse, ParsedApdu, SW_CONDITIONS_NOT_SATISFIED, SW_NO_ERROR, SW_REF_DATA_NOT_FOUND,
    SW_SECURITY_STATUS, SW_WRONG_P1P2,
};
use crate::applet::AppletVersion;
use keys::{Scp03Config, I_PARAM, KEY_DIVERSIFICATION_DATA};
use rand::RngCore;

/// Security level bits (GP Amendment D). Platform SCP uses 0x33.
pub const LEVEL_CMAC: u8 = 0x01;
pub const LEVEL_CDEC: u8 = 0x02;
pub const LEVEL_RMAC: u8 = 0x10;
pub const LEVEL_RENC: u8 = 0x20;
const SUPPORTED_LEVELS: [u8; 4] = [0x01, 0x03, 0x11, 0x33];

const SW_WRONG_LENGTH: u16 = 0x6700;

/// Per-connection SCP03 state.
#[derive(Default)]
pub enum Scp03State {
    #[default]
    Idle,
    /// After INITIALIZE UPDATE, awaiting EXTERNAL AUTHENTICATE.
    Pending(Pending),
    /// Authenticated secure channel.
    Active(Session),
}

/// Session keys and challenges retained between INITIALIZE UPDATE and
/// EXTERNAL AUTHENTICATE.
pub struct Pending {
    host_challenge: [u8; 8],
    card_challenge: [u8; 8],
    s_enc: Vec<u8>,
    s_mac: Vec<u8>,
    s_rmac: Vec<u8>,
    legacy: bool,
}

/// Established secure channel state.
pub struct Session {
    s_enc: Vec<u8>,
    s_mac: Vec<u8>,
    s_rmac: Vec<u8>,
    security_level: u8,
    /// MAC chaining value (advanced by each C-MAC; R-MAC does not advance it).
    mcv: [u8; 16],
    /// Command counter, 1 after EXTERNAL AUTHENTICATE.
    cmd_counter: u32,
    /// Plaintext data length of the command just unwrapped. Drives the
    /// response-ICV counter and the counter-advance rule in legacy mode.
    last_cmd_len: usize,
    /// Pre-4.3 applet Platform SCP semantics. The host middleware switches
    /// behaviour on the applet version: `fsl_sss_se05x_apis.c` tags the
    /// session `kSSS_AuthType_AESKey` when `appletVersion` is at least
    /// `0x04030000`, and `kSSS_AuthType_SCP03` below that. The two differ in
    /// *both* the command-counter advance rule and the response ICV.
    ///
    /// * Applet 4.3 and newer (SE051 / SE050E 7.2.0): the counter advances
    ///   after every command; the response ICV always uses the current
    ///   counter.
    /// * Older applets (SE050C 3.1.1): the counter advances only when the
    ///   command carried a body (for an error response, only when that body
    ///   was not exactly 8 bytes), and the response ICV of a body-less
    ///   command uses `counter - 1`.
    legacy: bool,
}

impl Scp03State {
    pub fn new() -> Self {
        Scp03State::Idle
    }

    /// Tear down any secure channel (chip reset, SELECT, MAC failure).
    pub fn reset(&mut self) {
        *self = Scp03State::Idle;
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Scp03State::Pending(_))
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Scp03State::Active(_))
    }

    /// INITIALIZE UPDATE (CLA 0x80 INS 0x50). Valid from any state; restarts
    /// the handshake. P1 is the requested key version number. The 8-byte host
    /// challenge is the command data field.
    pub fn initialize_update(&mut self, p1: u8, host_challenge: &[u8]) -> ApduResponse {
        let version = AppletVersion::from_env();
        self.initialize_update_with_config(
            p1,
            host_challenge,
            version,
            Scp03Config::from_env(version),
        )
    }

    pub fn initialize_update_with_config(
        &mut self,
        p1: u8,
        host_challenge: &[u8],
        version: AppletVersion,
        cfg: Scp03Config,
    ) -> ApduResponse {
        if host_challenge.len() != 8 {
            *self = Scp03State::Idle;
            return ApduResponse::error(SW_WRONG_LENGTH);
        }
        // Applet versions below 4.3 get the older Platform SCP semantics.
        let legacy = matches!(version, AppletVersion::V3_1_1);

        let mut host_ch = [0u8; 8];
        host_ch.copy_from_slice(host_challenge);
        let mut card_ch = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut card_ch);

        let Some((s_enc, s_mac, s_rmac)) =
            crypto::derive_session_keys(&cfg.enc, &cfg.mac, &host_ch, &card_ch)
        else {
            *self = Scp03State::Idle;
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        };
        let Some(card_crypto) =
            crypto::cryptogram(&s_mac, &host_ch, &card_ch, crypto::DDC_CARD_CRYPTOGRAM)
        else {
            *self = Scp03State::Idle;
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        };

        // Key version handling differs by applet generation (both bench-
        // verified, with P1 = 0x00 / 0x0b / 0x0c):
        //
        // * 7.2.0 (SE050E): INITIALIZE UPDATE never validates the key version.
        //   Even a bogus P1 returns 0x9000 and is echoed back in the key-info
        //   bytes; the wrong key is only caught at EXTERNAL AUTHENTICATE, when
        //   the cryptogram fails to verify.
        // * 3.1.1 (SE050C): the applet checks the key version up front and
        //   refuses an unknown one with 0x6A88, so the response always carries
        //   the configured KVN.
        let resp_kvn = if p1 == 0x00 { cfg.kvn } else { p1 };
        if legacy && p1 != 0x00 && p1 != cfg.kvn {
            *self = Scp03State::Idle;
            return ApduResponse::error(SW_REF_DATA_NOT_FOUND);
        }

        // 29-byte body: key-div(10) || KVN || SCP id (0x03) || i-param ||
        // card challenge(8) || card cryptogram(8). i-param 0x00 => no
        // trailing 3-byte sequence counter (bench-verified).
        let mut data = Vec::with_capacity(29);
        data.extend_from_slice(&KEY_DIVERSIFICATION_DATA);
        data.push(resp_kvn);
        data.push(0x03);
        data.push(I_PARAM);
        data.extend_from_slice(&card_ch);
        data.extend_from_slice(&card_crypto);

        *self = Scp03State::Pending(Pending {
            host_challenge: host_ch,
            card_challenge: card_ch,
            s_enc,
            s_mac,
            s_rmac,
            legacy,
        });
        ApduResponse::success_with_data(data)
    }

    /// EXTERNAL AUTHENTICATE (CLA 0x84 INS 0x82). `raw` is the full APDU:
    /// 84 82 <level> 00 10 <host cryptogram 8> <C-MAC 8>. Any failure drops
    /// the channel to Idle.
    pub fn external_authenticate(&mut self, raw: &[u8]) -> ApduResponse {
        // Take the pending state out; every failure path leaves us Idle.
        let p = match std::mem::replace(self, Scp03State::Idle) {
            Scp03State::Pending(p) => p,
            other => {
                *self = other;
                return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
            }
        };

        if raw.len() < 21 || raw[4] != 0x10 {
            return ApduResponse::error(SW_WRONG_LENGTH);
        }
        let level = raw[2];
        if !SUPPORTED_LEVELS.contains(&level) {
            return ApduResponse::error(SW_WRONG_P1P2);
        }
        let host_crypto_recv = &raw[5..13];
        let cmac_recv = &raw[13..21];

        let Some(expect_host) =
            crypto::cryptogram(&p.s_mac, &p.host_challenge, &p.card_challenge, crypto::DDC_HOST_CRYPTOGRAM)
        else {
            return ApduResponse::error(SW_SECURITY_STATUS);
        };
        // C-MAC over the initial (all-zero) MCV || header(5) || host cryptogram.
        let zero_mcv = [0u8; 16];
        let Some(full) = crypto::cmac_chain(&p.s_mac, &zero_mcv, &raw[0..13]) else {
            return ApduResponse::error(SW_SECURITY_STATUS);
        };
        if expect_host != host_crypto_recv[..] || full[..8] != cmac_recv[..] {
            return ApduResponse::error(SW_SECURITY_STATUS);
        }

        *self = Scp03State::Active(Session {
            s_enc: p.s_enc,
            s_mac: p.s_mac,
            s_rmac: p.s_rmac,
            security_level: level,
            mcv: full,
            cmd_counter: 1,
            last_cmd_len: 0,
            legacy: p.legacy,
        });
        // Bench-verified: the EXTERNAL AUTHENTICATE success response is a bare
        // plain 0x9000 (not R-MAC protected).
        ApduResponse::success()
    }
}

impl Session {
    /// Unwrap a secured command: verify the C-MAC, decrypt the data field if
    /// C-DECRYPTION is active, and return the inner plain APDU for dispatch.
    /// A MAC/padding failure returns Err(SW) and the caller drops the session.
    pub fn unwrap_command(&mut self, raw: &[u8]) -> Result<ParsedApdu, u16> {
        if raw.len() < 5 {
            return Err(SW_WRONG_LENGTH);
        }
        let (cla, ins, p1, p2) = (raw[0], raw[1], raw[2], raw[3]);
        // Lc is short (1 byte) or extended (0x00 hi lo). The MAC covers the
        // header and Lc exactly as transmitted, so read them raw.
        let (lc, data_start) = if raw[4] != 0x00 {
            (raw[4] as usize, 5usize)
        } else {
            if raw.len() < 7 {
                return Err(SW_WRONG_LENGTH);
            }
            (((raw[5] as usize) << 8) | raw[6] as usize, 7usize)
        };
        // The data field must at least hold the 8-byte C-MAC.
        if lc < 8 || data_start + lc > raw.len() {
            return Err(SW_WRONG_LENGTH);
        }
        let header_and_lc = &raw[..data_start];
        let body = &raw[data_start..data_start + lc];
        let le = match &raw[data_start + lc..] {
            [] => None,
            [b] => Some(*b as u16),
            [hi, lo, ..] => Some(((*hi as u16) << 8) | *lo as u16),
        };
        let (payload, cmac_recv) = body.split_at(lc - 8);
        let had_body = !payload.is_empty();

        // Verify C-MAC over MCV || header+Lc || encrypted payload.
        let mut mac_data = Vec::with_capacity(header_and_lc.len() + payload.len());
        mac_data.extend_from_slice(header_and_lc);
        mac_data.extend_from_slice(payload);
        let full = crypto::cmac_chain(&self.s_mac, &self.mcv, &mac_data).ok_or(SW_SECURITY_STATUS)?;
        if full[..8] != cmac_recv[..] {
            return Err(SW_SECURITY_STATUS);
        }
        self.mcv = full;

        let plaintext = if had_body && (self.security_level & LEVEL_CDEC != 0) {
            if payload.len() % 16 != 0 {
                return Err(SW_SECURITY_STATUS);
            }
            let icv = crypto::counter_icv(&self.s_enc, self.cmd_counter, false)
                .ok_or(SW_SECURITY_STATUS)?;
            let dec =
                crypto::cbc_crypt(&self.s_enc, &icv, payload, false).ok_or(SW_SECURITY_STATUS)?;
            crypto::unpad_m2(&dec).ok_or(SW_SECURITY_STATUS)?
        } else {
            payload.to_vec()
        };

        self.last_cmd_len = plaintext.len();

        Ok(ParsedApdu {
            cla: cla & !0x04, // clear the secure-messaging bit
            ins,
            p1,
            p2,
            data: plaintext,
            le,
        })
    }

    /// Wrap a response: R-ENCRYPT the data field (if active and non-empty),
    /// append the R-MAC, and advance the command counter.
    ///
    /// Only a success response is protected, which is exactly when the host
    /// unwraps one: `se05x_DeCrypt` calls `nxpSCP03_Decrypt_ResponseAPDU` only
    /// for `rv == SM_OK`, so an R-MAC appended to an error response would never
    /// be stripped and would surface as trailing garbage. A success response
    /// *with no data* still carries an R-MAC (a bare MAC+SW response, which is
    /// what the host's `rspBufLen == SCP_COMMAND_MAC_SIZE + SCP_GP_SW_LEN`
    /// branch exists to handle).
    pub fn wrap_response(&mut self, resp: ApduResponse) -> ApduResponse {
        let sw = resp.sw;
        let sw_bytes = [(sw >> 8) as u8, sw as u8];
        let has_data = !resp.data.is_empty();
        let protect = self.security_level & LEVEL_RMAC != 0 && sw == SW_NO_ERROR;
        let renc = self.security_level & LEVEL_RENC != 0;

        // Response ICV counter (nxpSCP03_Get_ResponseICV): the current command
        // counter, except that a pre-4.3 applet session reuses counter-1 when
        // the command carried no data body.
        let resp_counter = if self.legacy && self.last_cmd_len == 0 {
            self.cmd_counter.wrapping_sub(1)
        } else {
            self.cmd_counter
        };

        let out = if protect {
            let data_field = if renc && has_data {
                let padded = crypto::pad_m2(&resp.data);
                match crypto::counter_icv(&self.s_enc, resp_counter, true)
                    .and_then(|icv| crypto::cbc_crypt(&self.s_enc, &icv, &padded, true))
                {
                    Some(enc) => enc,
                    None => {
                        self.advance_counter(sw);
                        return ApduResponse::error(SW_SECURITY_STATUS);
                    }
                }
            } else {
                resp.data
            };
            let mut mac_in = data_field.clone();
            mac_in.extend_from_slice(&sw_bytes);
            match crypto::cmac_chain(&self.s_rmac, &self.mcv, &mac_in) {
                Some(full) => {
                    let mut data = data_field;
                    data.extend_from_slice(&full[..8]);
                    ApduResponse { data, sw }
                }
                None => {
                    self.advance_counter(sw);
                    return ApduResponse::error(SW_SECURITY_STATUS);
                }
            }
        } else {
            // Error response, or a security level without R-MAC: returned
            // unprotected (plain data, plain SW).
            ApduResponse { data: resp.data, sw }
        };

        self.advance_counter(sw);
        out
    }

    /// Advance the command counter per the host's rule for this applet
    /// generation. Applet >= 4.3 sessions advance after every command. Older
    /// applets advance only when the command carried a body, and for an error
    /// response only when that body was not exactly 8 bytes (see
    /// nxpSCP03_Decrypt_ResponseAPDU and the se05x_DeCrypt error path).
    fn advance_counter(&mut self, sw: u16) {
        let advance = if self.legacy {
            if sw == SW_NO_ERROR {
                self.last_cmd_len > 0
            } else {
                self.last_cmd_len != 8
            }
        } else {
            true
        };
        if advance {
            self.cmd_counter = self.cmd_counter.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_update_response_shape() {
        let mut st = Scp03State::new();
        let host_ch = [0u8; 8];
        let resp = st.initialize_update(0x00, &host_ch);
        assert_eq!(resp.sw, 0x9000);
        // key-div(10) + KVN + 0x03 + i-param + card challenge(8) + cryptogram(8)
        assert_eq!(resp.data.len(), 29);
        assert_eq!(resp.data[11], 0x03); // SCP03 id
        assert_eq!(resp.data[12], I_PARAM);
        assert_eq!(resp.data[10], keys::DEFAULT_KVN); // P1=0 -> configured KVN
        assert!(st.is_pending());
    }

    /// Key-version handling is applet-generation specific, both bench-verified.
    /// 7.2.0 accepts any key version at INITIALIZE UPDATE and echoes it back;
    /// 3.1.1 validates it up front and refuses an unknown one with 0x6A88.
    #[test]
    fn initialize_update_key_version_rules_per_applet_generation() {
        let restore = std::env::var("SE050_SIM_APPLET").ok();

        std::env::set_var("SE050_SIM_APPLET", "7.2.0");
        let mut st = Scp03State::new();
        let resp = st.initialize_update(0x0c, &[0u8; 8]);
        assert_eq!(resp.sw, 0x9000, "7.2.0 accepts any key version");
        assert_eq!(resp.data[10], 0x0c, "and echoes it back");

        std::env::set_var("SE050_SIM_APPLET", "3");
        let mut st = Scp03State::new();
        let resp = st.initialize_update(0x0c, &[0u8; 8]);
        assert_eq!(resp.sw, SW_REF_DATA_NOT_FOUND, "3.1.1 refuses a bad KVN");
        // The configured version and the "use the default" form still work.
        for p1 in [0x00, keys::DEFAULT_KVN] {
            let mut st = Scp03State::new();
            let resp = st.initialize_update(p1, &[0u8; 8]);
            assert_eq!(resp.sw, 0x9000, "p1={:#04x}", p1);
            assert_eq!(resp.data[10], keys::DEFAULT_KVN);
        }

        match restore {
            Some(v) => std::env::set_var("SE050_SIM_APPLET", v),
            None => std::env::remove_var("SE050_SIM_APPLET"),
        }
    }

    #[test]
    fn external_authenticate_without_pending_is_rejected() {
        let mut st = Scp03State::new();
        let resp = st.external_authenticate(&[0x84, 0x82, 0x33, 0x00, 0x10]);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    /// Build an Active session with known keys for the counter/ICV rule tests.
    fn test_session(legacy: bool, counter: u32, last_cmd_len: usize) -> Session {
        Session {
            s_enc: vec![0x11; 16],
            s_mac: vec![0x22; 16],
            s_rmac: vec![0x33; 16],
            security_level: 0x33,
            mcv: [0u8; 16],
            cmd_counter: counter,
            last_cmd_len,
            legacy,
        }
    }

    /// The response-encryption ICV counter differs by applet generation for a
    /// body-less command. Getting this wrong is silent on the wire (the R-MAC
    /// still verifies) but the host cannot decrypt the response -- it was the
    /// cause of "RAPDU Decoding failed No Padding found" against the real NXP
    /// middleware, so pin it explicitly here.
    #[test]
    fn response_icv_counter_rule_per_applet_generation() {
        let payload = vec![0xAB; 8];
        for (legacy, expect_counter) in [(false, 7u32), (true, 6u32)] {
            let mut sess = test_session(legacy, 7, 0); // body-less command
            let wrapped = sess.wrap_response(ApduResponse::success_with_data(payload.clone()));
            // Recompute the ciphertext the host would expect.
            let icv = crypto::counter_icv(&[0x11; 16], expect_counter, true).unwrap();
            let expected =
                crypto::cbc_crypt(&[0x11; 16], &icv, &crypto::pad_m2(&payload), true).unwrap();
            assert_eq!(
                &wrapped.data[..expected.len()],
                &expected[..],
                "legacy={} should use counter {}",
                legacy,
                expect_counter
            );
        }
    }

    /// A command that carried a body uses the current counter on both
    /// generations, so the two must agree there.
    #[test]
    fn response_icv_agrees_when_command_had_a_body() {
        let payload = vec![0xCD; 16];
        let mut a = test_session(false, 4, 24);
        let mut b = test_session(true, 4, 24);
        let wa = a.wrap_response(ApduResponse::success_with_data(payload.clone()));
        let wb = b.wrap_response(ApduResponse::success_with_data(payload));
        assert_eq!(wa.data, wb.data);
    }

    /// Only success responses are protected, and a success response with no
    /// data still carries an R-MAC (MAC + SW). An R-MAC on an error response
    /// would never be stripped by the host, which only unwraps SW 0x9000.
    #[test]
    fn only_success_responses_are_protected() {
        // Success, no data -> 8-byte R-MAC appended.
        let mut s = test_session(false, 3, 6);
        let r = s.wrap_response(ApduResponse::success());
        assert_eq!(r.sw, SW_NO_ERROR);
        assert_eq!(r.data.len(), 8, "no-data success should carry an R-MAC");

        // Error, no data -> bare status word.
        let mut s = test_session(false, 3, 6);
        let r = s.wrap_response(ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED));
        assert!(r.data.is_empty(), "error responses are unprotected");

        // A MAC-less security level leaves even success responses plain.
        let mut s = test_session(false, 3, 6);
        s.security_level = LEVEL_CMAC;
        let r = s.wrap_response(ApduResponse::success_with_data(vec![1, 2, 3]));
        assert_eq!(r.data, vec![1, 2, 3]);
    }

    #[test]
    fn counter_advance_rule_per_applet_generation() {
        // Applet >= 4.3: every command advances the counter.
        let mut s = test_session(false, 5, 0);
        s.wrap_response(ApduResponse::success());
        assert_eq!(s.cmd_counter, 6);

        // Pre-4.3: a body-less command does not advance it.
        let mut s = test_session(true, 5, 0);
        s.wrap_response(ApduResponse::success());
        assert_eq!(s.cmd_counter, 5);

        // Pre-4.3 with a body: advances.
        let mut s = test_session(true, 5, 24);
        s.wrap_response(ApduResponse::success());
        assert_eq!(s.cmd_counter, 6);

        // Pre-4.3 error response: advances unless the body was exactly 8 bytes.
        let mut s = test_session(true, 5, 8);
        s.wrap_response(ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED));
        assert_eq!(s.cmd_counter, 5);
        let mut s = test_session(true, 5, 6);
        s.wrap_response(ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED));
        assert_eq!(s.cmd_counter, 6);
    }

    #[test]
    fn bad_host_cryptogram_drops_to_idle() {
        let mut st = Scp03State::new();
        st.initialize_update(0x00, &[1u8; 8]);
        assert!(st.is_pending());
        // Garbage cryptogram + MAC.
        let mut apdu = vec![0x84, 0x82, 0x33, 0x00, 0x10];
        apdu.extend_from_slice(&[0xAAu8; 16]);
        let resp = st.external_authenticate(&apdu);
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
        assert!(matches!(st, Scp03State::Idle));
    }
}
