/* certs.rs
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

//! X.509 certificate store provisioning.
//!
//! A real TROPIC01 carries four certificates, which GET_INFO returns in this
//! order:
//!
//! 0. the device certificate: X25519 key (STPUB), key agreement only,
//!    signed by (1) with ecdsa-with-SHA384;
//! 1. the "TROPIC01-X CA": P-384, pathlen 0, signed by (2) with SHA-384;
//! 2. a P-384 cross certificate of the root CA, signed by (3) with SHA-512;
//! 3. the self-signed P-521 root, ecdsa-with-SHA512.
//!
//! The simulator generates a chain of the same shape at provisioning time
//! under its own root ("TROPIC01Sim Root CA v1"), so host code that parses
//! the store, extracts STPUB or verifies the chain can be exercised
//! end-to-end. The chain does NOT validate against Tropic Square's roots.

use std::time::{SystemTime, UNIX_EPOCH};

use p384::ecdsa::{signature::Signer as _, Signature as P384Signature, SigningKey as P384Key};
use p521::ecdsa::{Signature as P521Signature, SigningKey as P521Key, VerifyingKey as P521Public};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const OID_COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
const OID_ORG: &[u8] = &[0x55, 0x04, 0x0a];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_SECP521R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_AKI: &[u8] = &[0x55, 0x1d, 0x23];

const ORG: &str = "wolfSSL Inc. (TROPIC01Sim)";
const ROOT_CN: &str = "TROPIC01Sim Root CA v1";
const XCA_CN: &str = "TROPIC01Sim-X CA v1";

/// Number of 128-byte GET_INFO blocks the certificate store spans
/// (`TR01_L2_GET_INFO_REQ_CERT_SIZE_TOTAL` = 3840 bytes).
pub const CERT_STORE_BLOCKS: usize = 30;
pub const CERT_STORE_BLOCK_SIZE: usize = 128;

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n <= 0xff {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

fn oid(encoded: &[u8]) -> Vec<u8> {
    tlv(0x06, encoded)
}

fn integer(be: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = be.iter().copied().skip_while(|&b| b == 0).collect();
    if v.is_empty() || v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    tlv(0x02, &v)
}

fn bit_string(bytes: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut v = vec![unused_bits];
    v.extend_from_slice(bytes);
    tlv(0x03, &v)
}

fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

fn printable(s: &str) -> Vec<u8> {
    tlv(0x13, s.as_bytes())
}

/// X.509 time: UTCTime before 2050, GeneralizedTime from 2050 on.
fn x509_time(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> Vec<u8> {
    if y < 2050 {
        let t = format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100);
        tlv(0x17, t.as_bytes())
    } else {
        let t = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
        tlv(0x18, t.as_bytes())
    }
}

/// Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

struct Validity {
    not_before: Vec<u8>,
    year: i64,
    rest: (u32, u32, u32, u32, u32),
}

impl Validity {
    fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
        let tod = secs.rem_euclid(86_400);
        let (h, mi, s) = (
            (tod / 3600) as u32,
            ((tod / 60) % 60) as u32,
            (tod % 60) as u32,
        );
        Self {
            not_before: x509_time(y, mo, d, h, mi, s),
            year: y,
            rest: (mo, d.min(28), h, mi, s),
        }
    }

    fn for_years(&self, years: i64) -> Vec<u8> {
        let (mo, d, h, mi, s) = self.rest;
        seq(&[
            self.not_before.clone(),
            x509_time(self.year + years, mo, d, h, mi, s),
        ])
    }
}

fn name(country_and_org: bool, cn: &str) -> Vec<u8> {
    let mut rdns = Vec::new();
    if country_and_org {
        rdns.push(set(&[seq(&[oid(OID_COUNTRY), printable("US")])]));
        rdns.push(set(&[seq(&[oid(OID_ORG), utf8(ORG)])]));
    }
    rdns.push(set(&[seq(&[oid(OID_CN), utf8(cn)])]));
    seq(&rdns)
}

fn extension(id: &[u8], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![oid(id)];
    if critical {
        parts.push(vec![0x01, 0x01, 0xff]);
    }
    parts.push(tlv(0x04, &value));
    seq(&parts)
}

fn key_id(spki_key_bits: &[u8]) -> Vec<u8> {
    Sha256::digest(spki_key_bits)[..20].to_vec()
}

enum Issuer<'a> {
    P384(&'a P384Key),
    P521(&'a P521Key),
}

struct CertSpec<'a> {
    serial: Vec<u8>,
    issuer_name: Vec<u8>,
    subject_name: Vec<u8>,
    validity: Vec<u8>,
    spki: Vec<u8>,
    /// Basic constraints content (inside the extension's OCTET STRING).
    basic_constraints: Vec<u8>,
    key_usage: Vec<u8>,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
    issuer: Issuer<'a>,
}

fn build_cert(spec: CertSpec) -> Vec<u8> {
    let sig_oid = match spec.issuer {
        Issuer::P384(_) => OID_ECDSA_SHA384,
        Issuer::P521(_) => OID_ECDSA_SHA512,
    };
    let mut exts = vec![
        extension(OID_BASIC_CONSTRAINTS, true, spec.basic_constraints),
        extension(OID_KEY_USAGE, true, spec.key_usage),
    ];
    if let Some(ski) = spec.ski {
        exts.push(extension(OID_SKI, false, tlv(0x04, &ski)));
    }
    if let Some(aki) = spec.aki {
        exts.push(extension(OID_AKI, false, seq(&[tlv(0x80, &aki)])));
    }
    let tbs = seq(&[
        tlv(0xa0, &integer(&[2])),
        integer(&spec.serial),
        seq(&[oid(sig_oid)]),
        spec.issuer_name,
        spec.validity,
        spec.subject_name,
        spec.spki,
        tlv(0xa3, &seq(&exts)),
    ]);
    let sig_der = match spec.issuer {
        Issuer::P384(k) => {
            let sig: P384Signature = k.sign(&tbs);
            sig.to_der().as_bytes().to_vec()
        }
        Issuer::P521(k) => {
            let sig: P521Signature = k.sign(&tbs);
            sig.to_der().as_bytes().to_vec()
        }
    };
    seq(&[tbs, seq(&[oid(sig_oid)]), bit_string(&sig_der, 0)])
}

fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
    seq(&[
        seq(&[oid(OID_EC_PUBLIC_KEY), oid(curve_oid)]),
        bit_string(point, 0),
    ])
}

/// Basic constraints content: CA:FALSE, or CA:TRUE with an optional path
/// length.
fn basic_constraints(ca: bool, pathlen: Option<u8>) -> Vec<u8> {
    if !ca {
        return seq(&[]);
    }
    let mut parts = vec![vec![0x01, 0x01, 0xff]];
    if let Some(p) = pathlen {
        parts.push(integer(&[p]));
    }
    seq(&parts)
}

/// Build the four certificates (device, X CA, cross root, root) for a
/// device whose X25519 static public key is `st_pub`.
pub fn build_chain(st_pub: &[u8; 32], serial: &[u8; 8]) -> [Vec<u8>; 4] {
    let validity = Validity::now();

    let root_key = P521Key::random(&mut OsRng);
    let root_point = P521Public::from(&root_key).to_encoded_point(false);
    let root_spki = ec_spki(OID_SECP521R1, root_point.as_bytes());
    let root_kid = key_id(root_point.as_bytes());

    let mid_key = P384Key::random(&mut OsRng);
    let mid_point = mid_key.verifying_key().to_encoded_point(false);
    let mid_spki = ec_spki(OID_SECP384R1, mid_point.as_bytes());
    let mid_kid = key_id(mid_point.as_bytes());

    let xca_key = P384Key::random(&mut OsRng);
    let xca_point = xca_key.verifying_key().to_encoded_point(false);
    let xca_spki = ec_spki(OID_SECP384R1, xca_point.as_bytes());
    let xca_kid = key_id(xca_point.as_bytes());

    let root_name = name(true, ROOT_CN);
    let xca_name = name(true, XCA_CN);

    let root = build_cert(CertSpec {
        serial: vec![0x65],
        issuer_name: root_name.clone(),
        subject_name: root_name.clone(),
        validity: validity.for_years(50),
        spki: root_spki,
        basic_constraints: basic_constraints(true, None),
        key_usage: bit_string(&[0x06], 1),
        ski: Some(root_kid.clone()),
        aki: None,
        issuer: Issuer::P521(&root_key),
    });

    let cross = build_cert(CertSpec {
        serial: vec![0x03, 0xe9],
        issuer_name: root_name.clone(),
        subject_name: root_name.clone(),
        validity: validity.for_years(40),
        spki: mid_spki,
        basic_constraints: basic_constraints(true, Some(1)),
        key_usage: bit_string(&[0x06], 1),
        ski: Some(mid_kid.clone()),
        aki: Some(root_kid),
        issuer: Issuer::P521(&root_key),
    });

    let xca = build_cert(CertSpec {
        serial: vec![0x27, 0x11],
        issuer_name: root_name,
        subject_name: xca_name.clone(),
        validity: validity.for_years(35),
        spki: xca_spki,
        basic_constraints: basic_constraints(true, Some(0)),
        key_usage: bit_string(&[0x04], 2),
        ski: Some(xca_kid.clone()),
        aki: Some(mid_kid),
        issuer: Issuer::P384(&mid_key),
    });

    let mut dev_serial = vec![0x01];
    dev_serial.extend_from_slice(serial);
    let device_cn = format!(
        "TROPIC01Sim eSE {}",
        serial
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    );
    let device = build_cert(CertSpec {
        serial: dev_serial,
        issuer_name: xca_name,
        subject_name: name(false, &device_cn),
        validity: validity.for_years(20),
        spki: seq(&[seq(&[oid(OID_X25519)]), bit_string(st_pub, 0)]),
        basic_constraints: basic_constraints(false, None),
        key_usage: bit_string(&[0x08], 3),
        ski: None,
        aki: Some(xca_kid),
        issuer: Issuer::P384(&xca_key),
    });

    [device, xca, cross, root]
}

/// The GET_INFO(X509_CERTIFICATE) blob:
/// `[version=1][num_certs=4][4 x BE u16 cert lengths][certs...]`.
pub fn build_cert_store(st_pub: &[u8; 32], serial: &[u8; 8]) -> Vec<u8> {
    let certs = build_chain(st_pub, serial);
    let mut out = vec![1u8, certs.len() as u8];
    for c in &certs {
        out.extend_from_slice(&(c.len() as u16).to_be_bytes());
    }
    for c in &certs {
        out.extend_from_slice(c);
    }
    assert!(out.len() <= CERT_STORE_BLOCKS * CERT_STORE_BLOCK_SIZE);
    out
}

/// Split a cert store blob into its certificates.
pub fn split_cert_store(blob: &[u8]) -> Vec<Vec<u8>> {
    let n = blob[1] as usize;
    let mut off = 2 + 2 * n;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let len = u16::from_be_bytes([blob[2 + 2 * i], blob[3 + 2 * i]]) as usize;
        out.push(blob[off..off + len].to_vec());
        off += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_745), (2026, 10, 19));
    }

    #[test]
    fn store_layout_and_stpub_position() {
        let st_pub = [0x5a; 32];
        let blob = build_cert_store(&st_pub, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(blob[0], 1);
        assert_eq!(blob[1], 4);
        let certs = split_cert_store(&blob);
        assert_eq!(certs.len(), 4);
        // Device cert carries an X25519 SPKI with STPUB.
        let mut needle = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
        ];
        needle.extend_from_slice(&st_pub);
        assert!(certs[0]
            .windows(needle.len())
            .any(|w| w == needle.as_slice()));
        // Certificates are DER SEQUENCEs with a two-byte length.
        for c in &certs {
            assert_eq!(c[0], 0x30);
            assert_eq!(c[1], 0x82);
            assert_eq!(u16::from_be_bytes([c[2], c[3]]) as usize + 4, c.len());
        }
    }
}
