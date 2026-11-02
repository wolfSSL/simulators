/* applet_session.rs
 *
 * Copyright (C) 2026 wolfSSL Inc. and Cardea Key contributors
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

//! Applet sessions (AN12543 3.6.2, 4.5.1): CreateSession, ProcessSessionCmd
//! and CloseSession, with ECKey authentication (AN12543 3.6.3.3, 4.5.4.1).
//!
//! An ECKey session is opened against an Authentication Object holding a NIST
//! P-256 public key. The host proves possession of the private key with
//! ECKeySessionInternalAuthenticate: an ECDSA signature over the control
//! reference template and an ephemeral public key. A wrong signature counts
//! as a failed attempt of the Authentication Object; once its maximum is
//! reached the object no longer authenticates. On success the session keys
//! come from ECDH between the ephemeral key and the SE's own key pair
//! (RESERVED_ID_ECKEY_SESSION), and every further command of the session is
//! SCP03-wrapped with them, inside the Platform SCP03 channel if one is open.
//! Commands run inside a session are evaluated with the session's
//! Authentication Object as the policy owner.
//!
//! The host side this mirrors is NXP Plug & Trust
//! (sss/src/se05x/fsl_sss_se05x_eckey.c and se05x_tlv.c).

use std::collections::HashMap;

use p256::ecdsa::signature::Verifier;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::apdu::*;
use crate::object_store::types::{ECCurve, SecureObject};
use crate::object_store::{ObjectStore, RESERVED_ID_ECKEY_SESSION};
use crate::scp03::crypto;
use crate::scp03::Session as ScpSession;
use crate::tlv::{self, Tlv, TAG_1, TAG_SESSION_ID};

pub const P2_SESSION_CREATE: u8 = 0x1B;
pub const P2_SESSION_CLOSE: u8 = 0x1C;
const INS_AUTH_OBJECT: u8 = 0x40;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const DDC_INITIAL_MCV: u8 = 0x08;

/// SE050_SIM_TRACE=1: log every command as dispatched (after any SCP03
/// unwrapping) with its status word, to stderr. For debugging a host.
pub fn trace(context: &str, apdu: &ParsedApdu, sw: u16) {
    if std::env::var("SE050_SIM_TRACE").map(|v| v == "1").unwrap_or(false) {
        let data: String = apdu.data.iter().take(48).map(|b| format!("{:02x}", b)).collect();
        eprintln!(
            "[trace] {:<8} {:02x} {:02x} {:02x} {:02x} [{}] {}{} -> {:04x}",
            context, apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.data.len(), data,
            if apdu.data.len() > 48 { "..." } else { "" }, sw
        );
    }
}

struct AppletSession {
    auth_id: [u8; 4],
    /// AuthState::instance of the Authentication Object when the session was
    /// created; the session is void once the object is gone or replaced.
    auth_instance: u64,
    /// None until ECKeySessionInternalAuthenticate succeeds.
    scp: Option<ScpSession>,
}

/// Per-connection applet sessions. Reset by SELECT and by a T=1 interface
/// soft reset or resync, as a chip reset ends them.
#[derive(Default)]
pub struct AppletSessions {
    sessions: HashMap<[u8; 8], AppletSession>,
}

impl AppletSessions {
    pub fn reset(&mut self) {
        self.sessions.clear();
    }

    /// Handles session management commands and the rules that depend on the
    /// channel state. Returns None for ordinary commands, which the caller
    /// dispatches in the default session.
    pub fn intercept(&mut self, apdu: &ParsedApdu, store: &mut ObjectStore, scp_active: bool) -> Option<ApduResponse> {
        store.set_session_owner([0; 4]);
        if apdu.cla != 0x80 && apdu.cla != 0x84 {
            return None;
        }
        let base_ins = apdu.base_ins();
        if base_ins == INS_MGMT && apdu.p2 == P2_SESSION_CREATE {
            return Some(self.create(apdu, store));
        }
        if base_ins == INS_PROCESS {
            return Some(self.process(apdu, store, scp_active));
        }
        // Authentication Objects are created only over an authenticated
        // channel: bench-verified for UserID (0x6985 in a plain session on
        // SE050C 3.1.1 and SE051 7.2.0); assumed alike for the other types.
        if base_ins == INS_WRITE && apdu.ins & INS_AUTH_OBJECT != 0 && !scp_active {
            return Some(ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED));
        }
        if base_ins == INS_READ {
            store.ensure_eckey_session_key();
        }
        None
    }

    fn create(&mut self, apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
        let Some(auth_id) = object_id(apdu) else {
            return ApduResponse::error(SW_WRONG_DATA);
        };
        // Only ECKey Authentication Objects (NIST P-256) are supported.
        let is_eckey = matches!(
            store.get(&auth_id),
            Some(SecureObject::ECPublicKey { curve: ECCurve::NistP256, .. })
                | Some(SecureObject::ECKeyPair { curve: ECCurve::NistP256, .. })
        );
        let Some(auth) = store.auth_state(&auth_id).filter(|_| is_eckey) else {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        };
        let mut id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut id);
        self.sessions.insert(id, AppletSession { auth_id, auth_instance: auth.instance, scp: None });
        ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &id)])
    }

    fn process(&mut self, apdu: &ParsedApdu, store: &mut ObjectStore, scp_active: bool) -> ApduResponse {
        let Ok(tlvs) = apdu.parse_tlvs() else {
            return ApduResponse::error(SW_WRONG_DATA);
        };
        let (Some(sid), Some(inner)) = (tlv::find_tlv(&tlvs, TAG_SESSION_ID), tlv::find_tlv(&tlvs, TAG_1)) else {
            return ApduResponse::error(SW_WRONG_DATA);
        };
        let Ok(sid): Result<[u8; 8], _> = sid.value.as_slice().try_into() else {
            return ApduResponse::error(SW_WRONG_DATA);
        };
        let raw = inner.value.clone();
        let Some(session) = self.sessions.get_mut(&sid) else {
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        };
        // A session ends with its Authentication Object (AN12543 3.6.4),
        // whoever deleted it; a new object under the same ID does not revive it.
        if store.auth_state(&session.auth_id).map(|a| a.instance) != Some(session.auth_instance) {
            self.sessions.remove(&sid);
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        }
        if raw.len() < 4 {
            return ApduResponse::error(SW_WRONG_DATA);
        }

        let Some(scp) = session.scp.as_mut() else {
            // Not authenticated yet: only the authentication (or closing).
            let Ok(cmd) = ParsedApdu::parse(&raw) else {
                return ApduResponse::error(SW_WRONG_DATA);
            };
            if cmd.ins == INS_INTERNAL_AUTHENTICATE {
                let auth_id = session.auth_id;
                let result = internal_authenticate(&cmd, auth_id, store);
                trace("eckauth", &cmd, result.as_ref().map(|_| SW_NO_ERROR).unwrap_or_else(|e| *e));
                return match result {
                    Ok((resp, scp)) => {
                        session.scp = Some(scp);
                        resp
                    }
                    Err(sw) => {
                        self.sessions.remove(&sid);
                        ApduResponse::error(sw)
                    }
                };
            }
            if cmd.base_ins() == INS_MGMT && cmd.p2 == P2_SESSION_CLOSE {
                self.sessions.remove(&sid);
                return ApduResponse::success();
            }
            return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
        };

        if raw[0] & 0x04 == 0 {
            self.sessions.remove(&sid);
            return ApduResponse::error(SW_SECURITY_STATUS);
        }
        let cmd = match scp.unwrap_command(&raw) {
            Ok(c) => c,
            Err(sw) => {
                if std::env::var("SE050_SIM_TRACE").map(|v| v == "1").unwrap_or(false) {
                    eprintln!("[trace] session  unwrap failed {:04x}, session closed", sw);
                }
                self.sessions.remove(&sid);
                return ApduResponse::error(sw);
            }
        };
        let closing = cmd.base_ins() == INS_MGMT && cmd.p2 == P2_SESSION_CLOSE;
        let resp = if closing {
            ApduResponse::success()
        } else if cmd.base_ins() == INS_PROCESS || (cmd.base_ins() == INS_MGMT && cmd.p2 == P2_SESSION_CREATE) {
            ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED)
        } else {
            store.set_session_owner(session.auth_id);
            if cmd.base_ins() == INS_READ {
                store.ensure_eckey_session_key();
            }
            let r = crate::dispatch::dispatch(&cmd, store, scp_active);
            store.set_session_owner([0; 4]);
            r
        };
        trace("session", &cmd, resp.sw);
        let wrapped = scp.wrap_response(resp);
        // The session also ends when its own Authentication Object is gone
        // (deleted from within the session, AN12543 3.6.4).
        if closing || !store.exists(&session.auth_id) {
            self.sessions.remove(&sid);
        }
        wrapped
    }
}

fn object_id(apdu: &ParsedApdu) -> Option<[u8; 4]> {
    let tlvs = apdu.parse_tlvs().ok()?;
    tlv::find_tlv(&tlvs, TAG_1)?.value.as_slice().try_into().ok()
}

/// One BER-TLV with 1- or 2-byte tag: (tag, value, total encoded length).
fn ber_tlv(data: &[u8]) -> Option<(u16, &[u8], usize)> {
    let mut i = 0;
    let mut tag = *data.first()? as u16;
    i += 1;
    if tag & 0x1F == 0x1F {
        tag = (tag << 8) | *data.get(i)? as u16;
        i += 1;
    }
    let mut len = *data.get(i)? as usize;
    i += 1;
    if len == 0x81 {
        len = *data.get(i)? as usize;
        i += 1;
    } else if len == 0x82 {
        len = ((*data.get(i)? as usize) << 8) | *data.get(i + 1)? as usize;
        i += 2;
    } else if len > 0x80 {
        return None;
    }
    let value = data.get(i..i + len)?;
    Some((tag, value, i + len))
}

fn find_ber(data: &[u8], want: u16) -> Option<&[u8]> {
    let mut rest = data;
    while !rest.is_empty() {
        let (tag, value, used) = ber_tlv(rest)?;
        if tag == want {
            return Some(value);
        }
        rest = &rest[used..];
    }
    None
}

/// ECKeySessionInternalAuthenticate. On success: the plain response (SE
/// challenge and receipt) and the session's SCP03 state.
fn internal_authenticate(cmd: &ParsedApdu, auth_id: [u8; 4], store: &mut ObjectStore) -> Result<(ApduResponse, ScpSession), u16> {
    let data = &cmd.data;
    // Layout: A6 {4F AID, 90 SCP params, 80 key type, 81 key length},
    //         7F49 {B0 host ephemeral public key, F0 curve}, 5F37 signature.
    let (t1, crt, n1) = ber_tlv(data).ok_or(SW_WRONG_DATA)?;
    let (t2, epk, n2) = ber_tlv(&data[n1..]).ok_or(SW_WRONG_DATA)?;
    let (t3, sig, _) = ber_tlv(&data[n1 + n2..]).ok_or(SW_WRONG_DATA)?;
    if t1 != 0xA6 || t2 != 0x7F49 || t3 != 0x5F37 {
        return Err(SW_WRONG_DATA);
    }
    let signed = &data[..n1 + n2];
    let scp_params = find_ber(crt, 0x90).ok_or(SW_WRONG_DATA)?;
    if scp_params.len() != 3 || scp_params[0] != 0xAB || scp_params[1] != 0x01 {
        return Err(SW_WRONG_DATA);
    }
    let level = scp_params[2];
    if level != 0x33 || find_ber(crt, 0x80) != Some(&[0x88][..]) || find_ber(crt, 0x81) != Some(&[0x10][..]) {
        return Err(SW_WRONG_DATA);
    }
    let host_epk = find_ber(epk, 0xB0).ok_or(SW_WRONG_DATA)?;
    if find_ber(epk, 0xF0) != Some(&[0x03][..]) {
        return Err(SW_WRONG_DATA);
    }

    if store.auth_blocked(&auth_id) {
        return Err(SW_CONDITIONS_NOT_SATISFIED);
    }
    let auth_pub = match store.get(&auth_id) {
        Some(SecureObject::ECPublicKey { public_key, .. }) | Some(SecureObject::ECKeyPair { public_key, .. }) => public_key.clone(),
        _ => return Err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let verified = p256::ecdsa::VerifyingKey::from_sec1_bytes(&auth_pub)
        .ok()
        .zip(p256::ecdsa::Signature::from_der(sig).ok())
        .map(|(vk, s)| vk.verify(signed, &s).is_ok())
        .unwrap_or(false);
    if !verified {
        store.auth_failed(&auth_id);
        return Err(SW_CONDITIONS_NOT_SATISFIED);
    }
    store.auth_succeeded(&auth_id);

    // Key agreement with the SE's own ECKey session key pair.
    store.ensure_eckey_session_key();
    let se_priv = match store.get(&RESERVED_ID_ECKEY_SESSION) {
        Some(SecureObject::ECKeyPair { private_key, .. }) => private_key.clone(),
        _ => return Err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let sk = p256::SecretKey::from_slice(&se_priv).map_err(|_| SW_CONDITIONS_NOT_SATISFIED)?;
    let pk = p256::PublicKey::from_sec1_bytes(host_epk).map_err(|_| SW_WRONG_DATA)?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());

    let mut rnd = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    // Master key: 16 MSBs of SHA-256(counter 00000001 || shared secret ||
    // SE random || SCP parameters 01 level || key type 88 || key length 10).
    let mut h = Sha256::new();
    h.update([0x00, 0x00, 0x00, 0x01]);
    h.update(shared.raw_secret_bytes());
    h.update(rnd);
    h.update([0x01, level, 0x88, 0x10]);
    let master = h.finalize()[..16].to_vec();

    let s_enc = crypto::kdf(&master, crypto::DDC_S_ENC, &[], 128).ok_or(SW_CONDITIONS_NOT_SATISFIED)?;
    let s_mac = crypto::kdf(&master, crypto::DDC_S_MAC, &[], 128).ok_or(SW_CONDITIONS_NOT_SATISFIED)?;
    let s_rmac = crypto::kdf(&master, crypto::DDC_S_RMAC, &[], 128).ok_or(SW_CONDITIONS_NOT_SATISFIED)?;
    let mcv_v = crypto::kdf(&master, DDC_INITIAL_MCV, &[], 128).ok_or(SW_CONDITIONS_NOT_SATISFIED)?;
    let receipt = crate::handlers::mac::cmac_aes(&s_rmac, signed).ok_or(SW_CONDITIONS_NOT_SATISFIED)?;
    let mut mcv = [0u8; 16];
    mcv.copy_from_slice(&mcv_v);

    let mut out = vec![0x85, 0x10];
    out.extend_from_slice(&rnd);
    out.extend_from_slice(&[0x86, 0x10]);
    out.extend_from_slice(&receipt[..16]);
    Ok((ApduResponse::success_with_data(out), ScpSession::from_keys(s_enc, s_mac, s_rmac, mcv, level)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    const AUTH_ID: [u8; 4] = [0x7D, 0xA0, 0x00, 0x01];
    const HMAC_ID: [u8; 4] = [0x7D, 0xA0, 0x00, 0x02];
    const AID: [u8; 16] = [0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00];

    fn apdu(raw: &[u8]) -> ParsedApdu {
        ParsedApdu::parse(raw).unwrap()
    }

    fn cmd(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![cla, ins, p1, p2];
        if !data.is_empty() {
            if data.len() < 256 {
                v.push(data.len() as u8);
            } else {
                v.extend_from_slice(&[0, (data.len() >> 8) as u8, data.len() as u8]);
            }
            v.extend_from_slice(data);
        }
        v
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        Tlv::new(tag, value).encode()
    }

    fn run(sessions: &mut AppletSessions, store: &mut ObjectStore, raw: &[u8]) -> ApduResponse {
        let a = apdu(raw);
        sessions.intercept(&a, store, true).unwrap_or_else(|| crate::dispatch::dispatch(&a, store, true))
    }

    /// Store with an ECKey Authentication Object (max 3 attempts, delete only
    /// for itself) and an HMAC key that only it may use to sign.
    fn setup(auth: &p256::ecdsa::SigningKey) -> (ObjectStore, AppletSessions) {
        let mut store = ObjectStore::new();
        let mut s = AppletSessions::default();
        let pubkey = auth.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let mut policy = vec![8];
        policy.extend_from_slice(&AUTH_ID);
        policy.extend_from_slice(&crate::policy::POLICY_OBJ_ALLOW_DELETE.to_be_bytes());
        let mut data = tlv(crate::tlv::TAG_POLICY, &policy);
        data.extend(tlv(crate::tlv::TAG_MAX_ATTEMPTS, &[0x00, 0x03]));
        data.extend(tlv(TAG_1, &AUTH_ID));
        data.extend(tlv(crate::tlv::TAG_2, &[0x03]));
        data.extend(tlv(crate::tlv::TAG_4, &pubkey));
        let r = run(&mut s, &mut store, &cmd(0x80, INS_WRITE | 0x40, P1_EC | P1_PUBLIC_KEY, 0x00, &data));
        assert_eq!(r.sw, SW_NO_ERROR);

        let mut hp = vec![8];
        hp.extend_from_slice(&AUTH_ID);
        hp.extend_from_slice(&crate::policy::POLICY_OBJ_ALLOW_SIGN.to_be_bytes());
        hp.push(8);
        hp.extend_from_slice(&[0; 4]);
        hp.extend_from_slice(&crate::policy::POLICY_OBJ_ALLOW_DELETE.to_be_bytes());
        let mut data = tlv(crate::tlv::TAG_POLICY, &hp);
        data.extend(tlv(TAG_1, &HMAC_ID));
        data.extend(tlv(crate::tlv::TAG_3, &[0x5A; 32]));
        let r = run(&mut s, &mut store, &cmd(0x80, INS_WRITE, P1_HMAC, 0x00, &data));
        assert_eq!(r.sw, SW_NO_ERROR);
        (store, s)
    }

    fn create(s: &mut AppletSessions, store: &mut ObjectStore) -> [u8; 8] {
        let r = run(s, store, &cmd(0x80, INS_MGMT, 0x00, P2_SESSION_CREATE, &tlv(TAG_1, &AUTH_ID)));
        assert_eq!(r.sw, SW_NO_ERROR);
        let t = crate::tlv::parse_tlvs(&r.data).unwrap();
        tlv::find_tlv(&t, TAG_1).unwrap().value.as_slice().try_into().unwrap()
    }

    fn process(s: &mut AppletSessions, store: &mut ObjectStore, sid: &[u8; 8], inner: &[u8]) -> ApduResponse {
        let mut data = tlv(TAG_SESSION_ID, sid);
        data.extend(tlv(TAG_1, inner));
        run(s, store, &cmd(0x80, INS_PROCESS, 0x00, 0x00, &data))
    }

    struct Host {
        s_enc: Vec<u8>,
        s_mac: Vec<u8>,
        s_rmac: Vec<u8>,
        mcv: [u8; 16],
        counter: u32,
    }

    /// Host side of ECKeySessionInternalAuthenticate, as fsl_sss_se05x_eckey.c.
    fn authenticate(s: &mut AppletSessions, store: &mut ObjectStore, sid: &[u8; 8], auth: &p256::ecdsa::SigningKey) -> Result<Host, u16> {
        let eph = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let eph_pub = eph.public_key().to_encoded_point(false).as_bytes().to_vec();
        let mut crt = tlv(0x4F, &AID);
        crt.extend(tlv(0x90, &[0xAB, 0x01, 0x33]));
        crt.extend(tlv(0x80, &[0x88]));
        crt.extend(tlv(0x81, &[0x10]));
        let mut signed = tlv(0xA6, &crt);
        let mut epk = tlv(0xB0, &eph_pub);
        epk.extend(tlv(0xF0, &[0x03]));
        signed.extend_from_slice(&[0x7F, 0x49, epk.len() as u8]);
        signed.extend(epk);
        let sig: p256::ecdsa::Signature = auth.sign(&signed);
        let der = sig.to_der();
        let mut data = signed.clone();
        data.extend_from_slice(&[0x5F, 0x37, der.as_bytes().len() as u8]);
        data.extend_from_slice(der.as_bytes());
        let r = process(s, store, sid, &cmd(0x84, INS_INTERNAL_AUTHENTICATE, 0, 0, &data));
        if r.sw != SW_NO_ERROR {
            return Err(r.sw);
        }
        assert_eq!(r.data.len(), 36);
        let rnd = &r.data[2..18];
        let receipt = &r.data[20..36];
        let se_pub = match store.get(&RESERVED_ID_ECKEY_SESSION) {
            Some(SecureObject::ECKeyPair { public_key, .. }) => p256::PublicKey::from_sec1_bytes(public_key).unwrap(),
            _ => panic!("no SE key"),
        };
        let shared = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), se_pub.as_affine());
        let mut h = Sha256::new();
        h.update([0, 0, 0, 1]);
        h.update(shared.raw_secret_bytes());
        h.update(rnd);
        h.update([0x01, 0x33, 0x88, 0x10]);
        let master = h.finalize()[..16].to_vec();
        let s_rmac = crypto::kdf(&master, crypto::DDC_S_RMAC, &[], 128).unwrap();
        assert_eq!(&crate::handlers::mac::cmac_aes(&s_rmac, &signed).unwrap()[..16], receipt, "receipt");
        let mut mcv = [0u8; 16];
        mcv.copy_from_slice(&crypto::kdf(&master, DDC_INITIAL_MCV, &[], 128).unwrap());
        Ok(Host {
            s_enc: crypto::kdf(&master, crypto::DDC_S_ENC, &[], 128).unwrap(),
            s_mac: crypto::kdf(&master, crypto::DDC_S_MAC, &[], 128).unwrap(),
            s_rmac,
            mcv,
            counter: 1,
        })
    }

    impl Host {
        /// Wrap as se05x_Transform_scp (session case), send, unwrap as nxpSCP03_Decrypt_ResponseAPDU.
        fn call(&mut self, s: &mut AppletSessions, store: &mut ObjectStore, sid: &[u8; 8], cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> (Vec<u8>, u16) {
            let enc = if data.is_empty() {
                vec![]
            } else {
                let icv = crypto::counter_icv(&self.s_enc, self.counter, false).unwrap();
                crypto::cbc_crypt(&self.s_enc, &icv, &crypto::pad_m2(data), true).unwrap()
            };
            let mut inner = vec![cla | 0x04, ins, p1, p2, (enc.len() + 8) as u8];
            inner.extend_from_slice(&enc);
            self.mcv = crypto::cmac_chain(&self.s_mac, &self.mcv, &inner).unwrap();
            inner.extend_from_slice(&self.mcv[..8]);
            let r = process(s, store, sid, &inner);
            let counter = self.counter;
            self.counter += 1;
            if r.sw != SW_NO_ERROR {
                return (r.data, r.sw);
            }
            let (body, mac) = r.data.split_at(r.data.len() - 8);
            let mut mac_in = body.to_vec();
            mac_in.extend_from_slice(&[0x90, 0x00]);
            let full = crypto::cmac_chain(&self.s_rmac, &self.mcv, &mac_in).unwrap();
            assert_eq!(&full[..8], mac, "R-MAC");
            if body.is_empty() {
                return (vec![], r.sw);
            }
            let icv = crypto::counter_icv(&self.s_enc, counter, true).unwrap();
            (crypto::unpad_m2(&crypto::cbc_crypt(&self.s_enc, &icv, body, false).unwrap()).unwrap(), r.sw)
        }
    }

    fn hmac_cmd() -> Vec<u8> {
        let mut d = tlv(TAG_1, &HMAC_ID);
        d.extend(tlv(crate::tlv::TAG_2, &[0x19])); // kSE05x_MACAlgo_HMAC_SHA256
        d.extend(tlv(crate::tlv::TAG_3, b"pin-kek"));
        d
    }

    #[test]
    fn eckey_session_counts_blocks_and_scopes_policy() {
        let good = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let bad = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (mut store, mut s) = setup(&good);

        // Authentication Objects: not readable without READ in their policy,
        // not creatable outside an authenticated channel.
        let r = s.intercept(&apdu(&cmd(0x80, INS_WRITE | 0x40, P1_EC | P1_PUBLIC_KEY, 0, &tlv(TAG_1, &[1, 2, 3, 4]))), &mut store, false);
        assert_eq!(r.unwrap().sw, SW_CONDITIONS_NOT_SATISFIED);
        let r = run(&mut s, &mut store, &cmd(0x80, INS_READ, 0, 0, &tlv(TAG_1, &AUTH_ID)));
        assert_ne!(r.sw, SW_NO_ERROR);

        // The HMAC key does not sign in the default session.
        let r = run(&mut s, &mut store, &cmd(0x80, INS_CRYPTO, P1_MAC, P2_GENERATE_ONESHOT, &hmac_cmd()));
        assert_eq!(r.sw, SW_COMMAND_NOT_ALLOWED);

        // A wrong key counts.
        let sid = create(&mut s, &mut store);
        assert_eq!(authenticate(&mut s, &mut store, &sid, &bad).err(), Some(SW_CONDITIONS_NOT_SATISFIED));
        assert_eq!(store.auth_state(&AUTH_ID).unwrap().attempts, 1);

        // The right key resets the counter; inside the session the key signs.
        let sid = create(&mut s, &mut store);
        let mut host = authenticate(&mut s, &mut store, &sid, &good).unwrap();
        assert_eq!(store.auth_state(&AUTH_ID).unwrap().attempts, 0);
        let (mac1, sw) = host.call(&mut s, &mut store, &sid, 0x80, INS_CRYPTO, P1_MAC, P2_GENERATE_ONESHOT, &hmac_cmd());
        assert_eq!(sw, SW_NO_ERROR);
        let (mac2, sw) = host.call(&mut s, &mut store, &sid, 0x80, INS_CRYPTO, P1_MAC, P2_GENERATE_ONESHOT, &hmac_cmd());
        assert_eq!(sw, SW_NO_ERROR);
        assert_eq!(mac1, mac2);
        // Attributes: attempts and maximum, readable in the session.
        let (attrs, sw) = host.call(&mut s, &mut store, &sid, 0x80, INS_READ, 0, P2_ATTRIBUTES, &tlv(TAG_1, &AUTH_ID));
        assert_eq!(sw, SW_NO_ERROR);
        let a = &crate::tlv::parse_tlvs(&attrs).unwrap()[0].value;
        assert_eq!((a[5], &a[6..8], &a[12..14]), (0x02, &[0, 0][..], &[0, 3][..]));
        let (_, sw) = host.call(&mut s, &mut store, &sid, 0x80, INS_MGMT, 0, P2_SESSION_CLOSE, &[]);
        assert_eq!(sw, SW_NO_ERROR);
        assert_eq!(process(&mut s, &mut store, &sid, &[0x84, 0x02, 0, 0]).sw, SW_CONDITIONS_NOT_SATISFIED);

        // Three wrong keys block it for good, even for the right key.
        for n in 1..=3 {
            let sid = create(&mut s, &mut store);
            assert!(authenticate(&mut s, &mut store, &sid, &bad).is_err());
            assert_eq!(store.auth_state(&AUTH_ID).unwrap().attempts, n);
        }
        let sid = create(&mut s, &mut store);
        assert_eq!(authenticate(&mut s, &mut store, &sid, &good).err(), Some(SW_CONDITIONS_NOT_SATISFIED));
        assert_eq!(store.auth_state(&AUTH_ID).unwrap().attempts, 3);

        // The default session may delete the HMAC key (policy rule for 0) but
        // not the Authentication Object (no rule for 0).
        let r = run(&mut s, &mut store, &cmd(0x80, INS_MGMT, 0, P2_DELETE_OBJECT, &tlv(TAG_1, &AUTH_ID)));
        assert_ne!(r.sw, SW_NO_ERROR);
        let r = run(&mut s, &mut store, &cmd(0x80, INS_MGMT, 0, P2_DELETE_OBJECT, &tlv(TAG_1, &HMAC_ID)));
        assert_eq!(r.sw, SW_NO_ERROR);
    }

    fn ec_auth_write(id: &[u8; 4], curve: u8, max: Option<&[u8]>, pubkey: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        if let Some(m) = max {
            data.extend(tlv(crate::tlv::TAG_MAX_ATTEMPTS, m));
        }
        data.extend(tlv(TAG_1, id));
        data.extend(tlv(crate::tlv::TAG_2, &[curve]));
        data.extend(tlv(crate::tlv::TAG_4, pubkey));
        cmd(0x80, INS_WRITE | 0x40, P1_EC | P1_PUBLIC_KEY, 0x00, &data)
    }

    #[test]
    fn reserved_session_key_is_read_only() {
        let good = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (mut store, mut s) = setup(&good);
        let r = run(&mut s, &mut store, &cmd(0x80, INS_READ, 0, 0, &tlv(TAG_1, &RESERVED_ID_ECKEY_SESSION)));
        assert_eq!(r.sw, SW_NO_ERROR, "public key read");
        let peer = p256::SecretKey::random(&mut rand::rngs::OsRng).public_key().to_encoded_point(false).as_bytes().to_vec();
        let mut ecdh = tlv(TAG_1, &RESERVED_ID_ECKEY_SESSION);
        ecdh.extend(tlv(crate::tlv::TAG_2, &peer));
        let mut sign = tlv(TAG_1, &RESERVED_ID_ECKEY_SESSION);
        sign.extend(tlv(crate::tlv::TAG_2, &[0x21]));
        sign.extend(tlv(crate::tlv::TAG_3, &[0x11; 32]));
        let mut ecdh_into = tlv(TAG_1, &HMAC_ID);
        ecdh_into.extend(tlv(crate::tlv::TAG_2, &peer));
        ecdh_into.extend(tlv(crate::tlv::TAG_7, &RESERVED_ID_ECKEY_SESSION));
        for (what, raw) in [
            ("ECDH", cmd(0x80, INS_CRYPTO, P1_EC, P2_DH, &ecdh)),
            ("sign", cmd(0x80, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, &sign)),
            ("ECDH into", cmd(0x80, INS_CRYPTO, P1_EC, P2_DH, &ecdh_into)),
            ("delete", cmd(0x80, INS_MGMT, 0, P2_DELETE_OBJECT, &tlv(TAG_1, &RESERVED_ID_ECKEY_SESSION))),
            ("replace", ec_auth_write(&RESERVED_ID_ECKEY_SESSION, 0x03, None, &peer)),
        ] {
            assert_eq!(run(&mut s, &mut store, &raw).sw, SW_CONDITIONS_NOT_SATISFIED, "{what}");
        }
        // Nor inside an authenticated session.
        let sid = create(&mut s, &mut store);
        let mut host = authenticate(&mut s, &mut store, &sid, &good).unwrap();
        let (_, sw) = host.call(&mut s, &mut store, &sid, 0x80, INS_CRYPTO, P1_EC, P2_DH, &ecdh);
        assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
        assert!(matches!(store.get(&RESERVED_ID_ECKEY_SESSION), Some(SecureObject::ECKeyPair { .. })));
    }

    #[test]
    fn key_pair_authentication_object_does_not_sign_for_others() {
        // A key-pair Authentication Object with no policy is read only
        // (AN12543 table 17): it cannot sign the authentication challenge
        // for a caller that lacks the private key.
        let mut store = ObjectStore::new();
        let mut s = AppletSessions::default();
        let mut data = tlv(TAG_1, &AUTH_ID);
        data.extend(tlv(crate::tlv::TAG_2, &[0x03]));
        let r = run(&mut s, &mut store, &cmd(0x80, INS_WRITE | 0x40, P1_EC | P1_KEY_PAIR, 0x00, &data));
        assert_eq!(r.sw, SW_NO_ERROR);
        let mut sign = tlv(TAG_1, &AUTH_ID);
        sign.extend(tlv(crate::tlv::TAG_2, &[0x21])); // ECDSA SHA-256
        sign.extend(tlv(crate::tlv::TAG_3, &[0x11; 32]));
        let r = run(&mut s, &mut store, &cmd(0x80, INS_CRYPTO, P1_SIGNATURE, P2_SIGN, &sign));
        assert_eq!(r.sw, SW_COMMAND_NOT_ALLOWED);
        let peer = p256::SecretKey::random(&mut rand::rngs::OsRng).public_key().to_encoded_point(false).as_bytes().to_vec();
        let mut ecdh = tlv(TAG_1, &AUTH_ID);
        ecdh.extend(tlv(crate::tlv::TAG_2, &peer));
        let r = run(&mut s, &mut store, &cmd(0x80, INS_CRYPTO, P1_EC, P2_DH, &ecdh));
        assert_eq!(r.sw, SW_COMMAND_NOT_ALLOWED);
    }

    #[test]
    fn sessions_end_when_their_authentication_object_is_deleted() {
        let good = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (mut store, mut s) = setup(&good);
        let pubkey = good.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let sid_a = create(&mut s, &mut store);
        let mut a = authenticate(&mut s, &mut store, &sid_a, &good).unwrap();
        let sid_b = create(&mut s, &mut store);
        let mut b = authenticate(&mut s, &mut store, &sid_b, &good).unwrap();
        let sid_pending = create(&mut s, &mut store);
        // Session B deletes the Authentication Object (its own policy allows
        // it), then the object is created again under the same ID.
        let (_, sw) = b.call(&mut s, &mut store, &sid_b, 0x80, INS_MGMT, 0, P2_DELETE_OBJECT, &tlv(TAG_1, &AUTH_ID));
        assert_eq!(sw, SW_NO_ERROR);
        let r = run(&mut s, &mut store, &ec_auth_write(&AUTH_ID, 0x03, None, &pubkey));
        assert_eq!(r.sw, SW_NO_ERROR);
        // Neither session A nor the half-open one survive, though the ID exists again.
        let (_, sw) = a.call(&mut s, &mut store, &sid_a, 0x80, INS_CRYPTO, P1_MAC, P2_GENERATE_ONESHOT, &hmac_cmd());
        assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
        assert_eq!(authenticate(&mut s, &mut store, &sid_pending, &good).err(), Some(SW_CONDITIONS_NOT_SATISFIED));
        assert_eq!(store.auth_state(&AUTH_ID).unwrap().attempts, 0, "a stale session costs no attempt");
        // A new session on the new object works.
        let sid = create(&mut s, &mut store);
        assert!(authenticate(&mut s, &mut store, &sid, &good).is_ok());
    }

    #[test]
    fn authentication_object_parameters_are_validated() {
        let mut store = ObjectStore::new();
        let mut s = AppletSessions::default();
        let p256_pub = p256::SecretKey::random(&mut rand::rngs::OsRng).public_key().to_encoded_point(false).as_bytes().to_vec();
        let p384_pub = p384::SecretKey::random(&mut rand::rngs::OsRng).public_key().to_encoded_point(false).as_bytes().to_vec();
        for (what, raw) in [
            ("max attempts, one byte", ec_auth_write(&AUTH_ID, 0x03, Some(&[0x03]), &p256_pub)),
            ("max attempts, three bytes", ec_auth_write(&AUTH_ID, 0x03, Some(&[0, 0, 3]), &p256_pub)),
            ("max attempts above 0x7FFF", ec_auth_write(&AUTH_ID, 0x03, Some(&[0x80, 0x00]), &p256_pub)),
            ("P-384", ec_auth_write(&AUTH_ID, 0x04, None, &p384_pub)),
        ] {
            assert_eq!(run(&mut s, &mut store, &raw).sw, SW_WRONG_DATA, "{what}");
            assert!(!store.exists(&AUTH_ID), "{what}: nothing stored");
        }
        let r = run(&mut s, &mut store, &ec_auth_write(&AUTH_ID, 0x03, Some(&[0x7F, 0xFF]), &p256_pub));
        assert_eq!(r.sw, SW_NO_ERROR);
        assert_eq!(store.auth_state(&AUTH_ID).unwrap().max_attempts, 0x7FFF);
    }
}
