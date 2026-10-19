/* l3.rs
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

//! L3 command processing (the plaintext inside an Encrypted_Cmd packet).
//!
//! Commands are `[cmd_id][fields...]` (`lt_l3_api_structs.h`); results are
//! `[result][fields...]`. Result codes and error precedence follow the
//! bench chip (see `HARDWARE_VALIDATION.md`) and, where the bench chip
//! could not be exercised safely, Tropic Square's ts-tvl model:
//!
//! * a slot or index outside the command's range is UNAUTHORIZED;
//! * every command is gated by its User Access Privilege register (the
//!   effective R-Config AND I-Config value), bit `pkey_index` of the 8-bit
//!   field covering the target;
//! * an L3 size that does not fit the command is handled per firmware
//!   personality (lenient on FW 0.1.2, L2 GEN_ERR + session close on 2.x).

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use ed25519_dalek::SigningKey as Ed25519Signing;
use p256::{
    ecdsa::{
        signature::hazmat::RandomizedPrehashSigner, Signature as P256Signature,
        SigningKey as P256Signing,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey as P256Secret,
};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha512};
use tiny_keccak::{Hasher, Kmac};

use crate::object_store::{CurveKind, Device, EccSlot, KeyOrigin, PairingSlot, PairingState};
use crate::personality::Personality;

pub mod result {
    pub const OK: u8 = 0xc3;
    pub const FAIL: u8 = 0x3c;
    pub const UNAUTHORIZED: u8 = 0x01;
    pub const INVALID_CMD: u8 = 0x02;
    pub const SLOT_NOT_EMPTY: u8 = 0x10;
    pub const SLOT_EXPIRED: u8 = 0x11;
    pub const INVALID_KEY: u8 = 0x12;
    pub const UPDATE_ERR: u8 = 0x13;
    pub const COUNTER_INVALID: u8 = 0x14;
    pub const SLOT_EMPTY: u8 = 0x15;
    pub const SLOT_INVALID: u8 = 0x16;
    pub const HARDWARE_FAIL: u8 = 0x17;
}

pub mod cmd_id {
    pub const PING: u8 = 0x01;
    pub const PAIRING_KEY_WRITE: u8 = 0x10;
    pub const PAIRING_KEY_READ: u8 = 0x11;
    pub const PAIRING_KEY_INVALIDATE: u8 = 0x12;
    pub const R_CONFIG_WRITE: u8 = 0x20;
    pub const R_CONFIG_READ: u8 = 0x21;
    pub const R_CONFIG_ERASE: u8 = 0x22;
    pub const I_CONFIG_WRITE: u8 = 0x30;
    pub const I_CONFIG_READ: u8 = 0x31;
    pub const R_MEM_DATA_WRITE: u8 = 0x40;
    pub const R_MEM_DATA_READ: u8 = 0x41;
    pub const R_MEM_DATA_ERASE: u8 = 0x42;
    pub const RANDOM_VALUE_GET: u8 = 0x50;
    pub const ECC_KEY_GENERATE: u8 = 0x60;
    pub const ECC_KEY_STORE: u8 = 0x61;
    pub const ECC_KEY_READ: u8 = 0x62;
    pub const ECC_KEY_ERASE: u8 = 0x63;
    pub const ECDSA_SIGN: u8 = 0x70;
    pub const EDDSA_SIGN: u8 = 0x71;
    pub const MCOUNTER_INIT: u8 = 0x80;
    pub const MCOUNTER_UPDATE: u8 = 0x81;
    pub const MCOUNTER_GET: u8 = 0x82;
    pub const MAC_AND_DESTROY: u8 = 0x90;
}

/// User Access Privilege register addresses.
mod uap {
    pub const PAIRING_KEY_WRITE: u16 = 0x020;
    pub const PAIRING_KEY_READ: u16 = 0x024;
    pub const PAIRING_KEY_INVALIDATE: u16 = 0x028;
    pub const R_CONFIG_WRITE_ERASE: u16 = 0x030;
    pub const R_CONFIG_READ: u16 = 0x034;
    pub const I_CONFIG_WRITE: u16 = 0x040;
    pub const I_CONFIG_READ: u16 = 0x044;
    pub const PING: u16 = 0x100;
    pub const R_MEM_DATA_WRITE: u16 = 0x110;
    pub const R_MEM_DATA_READ: u16 = 0x114;
    pub const R_MEM_DATA_ERASE: u16 = 0x118;
    pub const RANDOM_VALUE_GET: u16 = 0x120;
    pub const ECC_KEY_GENERATE: u16 = 0x130;
    pub const ECC_KEY_STORE: u16 = 0x134;
    pub const ECC_KEY_READ: u16 = 0x138;
    pub const ECC_KEY_ERASE: u16 = 0x13c;
    pub const ECDSA_SIGN: u16 = 0x140;
    pub const EDDSA_SIGN: u16 = 0x144;
    pub const MCOUNTER_INIT: u16 = 0x150;
    pub const MCOUNTER_GET: u16 = 0x154;
    pub const MCOUNTER_UPDATE: u16 = 0x158;
    pub const MAC_AND_DESTROY: u16 = 0x160;
}

const ECC_SLOT_MAX: u16 = 31;
const R_MEM_SLOT_MAX: u16 = 511;
const MCOUNTER_MAX: u16 = 15;
const MCOUNTER_VALUE_MAX: u32 = 0xffff_fffe;
const MACANDD_SLOT_MAX: u16 = 127;
const PING_MAX: usize = 4096;
const EDDSA_MSG_MAX: usize = 4096;
const CONFIG_OBJECT_SIZE: u16 = 0x200;
const MACANDD_CUSTOM: &[u8] = b"My Tagged Application";

/// What an L3 command produced.
#[derive(Debug, PartialEq, Eq)]
pub enum L3Outcome {
    /// A plaintext result to encrypt and return.
    Result(Vec<u8>),
    /// Reject at L2 with GEN_ERR and close the session (FW 2.x behavior for
    /// malformed command sizes).
    GenErr,
}

/// How FW 0.1.2 reacts to an L3 command whose size does not fit its ID.
enum Lenient {
    /// RESULT_FAIL.
    Fail,
    /// RESULT_OK with no result fields.
    OkNoData,
    /// Ignore the extra bytes and execute.
    Execute,
}

struct Ctx<'a> {
    dev: &'a mut Device,
    p: Personality,
    pkey: u8,
}

fn ok(fields: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + fields.len());
    v.push(result::OK);
    v.extend_from_slice(fields);
    v
}

fn code(c: u8) -> Vec<u8> {
    vec![c]
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

impl Ctx<'_> {
    /// UAP check: field at bit `pos` of register `addr`, bit `pkey`.
    fn allowed(&self, addr: u16, pos: u32) -> bool {
        (self.dev.config(addr) >> pos) & 0xff & (1u32 << self.pkey) != 0
    }
}

/// Acceptable command sizes (including the cmd_id byte).
fn size_ok(p: Personality, id: u8, len: usize) -> bool {
    use cmd_id::*;
    match id {
        PING => (1..=1 + PING_MAX).contains(&len),
        PAIRING_KEY_WRITE => len == 36,
        PAIRING_KEY_READ | PAIRING_KEY_INVALIDATE => len == 3,
        R_CONFIG_WRITE => len == 8,
        R_CONFIG_READ | I_CONFIG_READ => len == 3,
        R_CONFIG_ERASE => len == 1,
        I_CONFIG_WRITE => len == 4,
        R_MEM_DATA_WRITE => (5..=4 + p.r_mem_slot_max()).contains(&len),
        R_MEM_DATA_READ | R_MEM_DATA_ERASE => len == 3,
        RANDOM_VALUE_GET => len == 2,
        ECC_KEY_GENERATE => len == 4,
        ECC_KEY_STORE => len == 48,
        ECC_KEY_READ | ECC_KEY_ERASE => len == 3,
        ECDSA_SIGN => len == 48,
        EDDSA_SIGN => (16..=16 + EDDSA_MSG_MAX).contains(&len),
        MCOUNTER_INIT => len == 8,
        MCOUNTER_UPDATE | MCOUNTER_GET => len == 3,
        MAC_AND_DESTROY => len == 36,
        _ => true,
    }
}

/// FW 0.1.2 reactions to bad sizes, as observed on the bench chip.
/// Commands not exercised there are assumed to answer RESULT_FAIL.
fn es_lenient(id: u8, len: usize) -> Lenient {
    use cmd_id::*;
    match id {
        RANDOM_VALUE_GET if len > 2 => Lenient::Execute,
        ECDSA_SIGN | MAC_AND_DESTROY | EDDSA_SIGN => Lenient::OkNoData,
        _ => Lenient::Fail,
    }
}

pub fn dispatch(dev: &mut Device, p: Personality, pkey: u8, plaintext: &[u8]) -> L3Outcome {
    let Some(&id) = plaintext.first() else {
        return L3Outcome::Result(code(result::INVALID_CMD));
    };
    let known = matches!(
        id,
        cmd_id::PING
            | cmd_id::PAIRING_KEY_WRITE
            | cmd_id::PAIRING_KEY_READ
            | cmd_id::PAIRING_KEY_INVALIDATE
            | cmd_id::R_CONFIG_WRITE
            | cmd_id::R_CONFIG_READ
            | cmd_id::R_CONFIG_ERASE
            | cmd_id::I_CONFIG_WRITE
            | cmd_id::I_CONFIG_READ
            | cmd_id::R_MEM_DATA_WRITE
            | cmd_id::R_MEM_DATA_READ
            | cmd_id::R_MEM_DATA_ERASE
            | cmd_id::RANDOM_VALUE_GET
            | cmd_id::ECC_KEY_GENERATE
            | cmd_id::ECC_KEY_STORE
            | cmd_id::ECC_KEY_READ
            | cmd_id::ECC_KEY_ERASE
            | cmd_id::ECDSA_SIGN
            | cmd_id::EDDSA_SIGN
            | cmd_id::MCOUNTER_INIT
            | cmd_id::MCOUNTER_UPDATE
            | cmd_id::MCOUNTER_GET
            | cmd_id::MAC_AND_DESTROY
    );
    if !known {
        return L3Outcome::Result(code(result::INVALID_CMD));
    }

    let mut ctx = Ctx { dev, p, pkey };
    let c = plaintext;

    if !size_ok(p, id, c.len()) {
        if p.strict_l3_sizes() {
            return L3Outcome::GenErr;
        }
        match es_lenient(id, c.len()) {
            Lenient::Fail => return L3Outcome::Result(code(result::FAIL)),
            Lenient::OkNoData => return L3Outcome::Result(code(result::OK)),
            Lenient::Execute => {}
        }
    }

    L3Outcome::Result(match id {
        cmd_id::PING => ctx.ping(c),
        cmd_id::PAIRING_KEY_WRITE => ctx.pairing_key_write(c),
        cmd_id::PAIRING_KEY_READ => ctx.pairing_key_read(c),
        cmd_id::PAIRING_KEY_INVALIDATE => ctx.pairing_key_invalidate(c),
        cmd_id::R_CONFIG_WRITE => ctx.r_config_write(c),
        cmd_id::R_CONFIG_READ => ctx.config_read(c, false),
        cmd_id::R_CONFIG_ERASE => ctx.r_config_erase(),
        cmd_id::I_CONFIG_WRITE => ctx.i_config_write(c),
        cmd_id::I_CONFIG_READ => ctx.config_read(c, true),
        cmd_id::R_MEM_DATA_WRITE => ctx.r_mem_write(c),
        cmd_id::R_MEM_DATA_READ => ctx.r_mem_read(c),
        cmd_id::R_MEM_DATA_ERASE => ctx.r_mem_erase(c),
        cmd_id::RANDOM_VALUE_GET => ctx.random(c),
        cmd_id::ECC_KEY_GENERATE => ctx.ecc_generate(c),
        cmd_id::ECC_KEY_STORE => ctx.ecc_store(c),
        cmd_id::ECC_KEY_READ => ctx.ecc_read(c),
        cmd_id::ECC_KEY_ERASE => ctx.ecc_erase(c),
        cmd_id::ECDSA_SIGN => ctx.ecdsa_sign(c),
        cmd_id::EDDSA_SIGN => ctx.eddsa_sign(c),
        cmd_id::MCOUNTER_INIT => ctx.mcounter_init(c),
        cmd_id::MCOUNTER_UPDATE => ctx.mcounter_update(c),
        cmd_id::MCOUNTER_GET => ctx.mcounter_get(c),
        cmd_id::MAC_AND_DESTROY => ctx.mac_and_destroy(c),
        _ => code(result::INVALID_CMD),
    })
}

impl Ctx<'_> {
    /// Ping: `[0x01][data...]` -> `[OK][data...]`.
    fn ping(&mut self, c: &[u8]) -> Vec<u8> {
        if !self.allowed(uap::PING, 0) {
            return code(result::UNAUTHORIZED);
        }
        ok(&c[1..])
    }

    /// Pairing_Key_Write: `[0x10][slot u16][pad][s_hipub 32]`.
    fn pairing_key_write(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = u16_at(c, 1);
        if slot > 3 {
            return code(result::UNAUTHORIZED);
        }
        if !self.allowed(uap::PAIRING_KEY_WRITE, slot as u32 * 8) {
            return code(result::UNAUTHORIZED);
        }
        if self.dev.pairing_slots.contains_key(&(slot as u8)) {
            return code(result::FAIL);
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&c[4..36]);
        self.dev.pairing_slots.insert(
            slot as u8,
            PairingSlot {
                public_key,
                state: PairingState::Written,
            },
        );
        code(result::OK)
    }

    /// Pairing_Key_Read: `[0x11][slot u16]` -> `[OK][pad 3][s_hipub 32]`.
    fn pairing_key_read(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = u16_at(c, 1);
        if slot > 3 {
            return code(result::UNAUTHORIZED);
        }
        if !self.allowed(uap::PAIRING_KEY_READ, slot as u32 * 8) {
            return code(result::UNAUTHORIZED);
        }
        match self.dev.pairing_slots.get(&(slot as u8)) {
            None => code(result::SLOT_EMPTY),
            Some(s) if s.state == PairingState::Invalidated => code(result::SLOT_INVALID),
            Some(s) => {
                let mut f = vec![0u8; 3];
                f.extend_from_slice(&s.public_key);
                ok(&f)
            }
        }
    }

    /// Pairing_Key_Invalidate: `[0x12][slot u16]`.
    fn pairing_key_invalidate(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = u16_at(c, 1);
        if slot > 3 {
            return code(result::UNAUTHORIZED);
        }
        if !self.allowed(uap::PAIRING_KEY_INVALIDATE, slot as u32 * 8) {
            return code(result::UNAUTHORIZED);
        }
        match self.dev.pairing_slots.get_mut(&(slot as u8)) {
            None => code(result::FAIL),
            Some(s) => {
                s.state = PairingState::Invalidated;
                code(result::OK)
            }
        }
    }

    /// Address checks shared by the configuration commands. Configuration
    /// registers (0x000-0x0FC) use the `cfg` UAP field, functionality
    /// registers (0x100-0x1FC) the `func` field (bits 8..15).
    fn config_addr(&self, addr: u16, uap_addr: u16) -> Result<usize, u8> {
        if addr >= CONFIG_OBJECT_SIZE {
            return Err(result::UNAUTHORIZED);
        }
        let pos = if addr < 0x100 { 0 } else { 8 };
        if !self.allowed(uap_addr, pos) {
            return Err(result::UNAUTHORIZED);
        }
        if addr % 4 != 0 {
            return Err(result::FAIL);
        }
        Ok(addr as usize / 4)
    }

    /// R_Config_Write: `[0x20][addr u16][pad][value u32]`. Only an erased
    /// register can be written.
    fn r_config_write(&mut self, c: &[u8]) -> Vec<u8> {
        if !self.allowed(uap::R_CONFIG_WRITE_ERASE, 0) {
            return code(result::UNAUTHORIZED);
        }
        let addr = u16_at(c, 1);
        if addr >= CONFIG_OBJECT_SIZE {
            return code(result::UNAUTHORIZED);
        }
        if addr % 4 != 0 {
            return code(result::FAIL);
        }
        let i = addr as usize / 4;
        if self.dev.r_config[i] != 0xffff_ffff {
            return code(result::FAIL);
        }
        self.dev.r_config[i] = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        code(result::OK)
    }

    /// R_Config_Read / I_Config_Read: `[id][addr u16]` -> `[OK][pad 3][value]`.
    fn config_read(&mut self, c: &[u8], immutable: bool) -> Vec<u8> {
        let uap_addr = if immutable {
            uap::I_CONFIG_READ
        } else {
            uap::R_CONFIG_READ
        };
        let i = match self.config_addr(u16_at(c, 1), uap_addr) {
            Ok(i) => i,
            Err(e) => return code(e),
        };
        let v = if immutable {
            self.dev.i_config[i]
        } else {
            self.dev.r_config[i]
        };
        let mut f = vec![0u8; 3];
        f.extend_from_slice(&v.to_le_bytes());
        ok(&f)
    }

    fn r_config_erase(&mut self) -> Vec<u8> {
        if !self.allowed(uap::R_CONFIG_WRITE_ERASE, 0) {
            return code(result::UNAUTHORIZED);
        }
        for r in self.dev.r_config.iter_mut() {
            *r = 0xffff_ffff;
        }
        code(result::OK)
    }

    /// I_Config_Write: `[0x30][addr u16][bit_index]` clears one bit.
    fn i_config_write(&mut self, c: &[u8]) -> Vec<u8> {
        let i = match self.config_addr(u16_at(c, 1), uap::I_CONFIG_WRITE) {
            Ok(i) => i,
            Err(e) => return code(e),
        };
        let bit = c[3];
        if bit > 31 {
            return code(result::FAIL);
        }
        self.dev.i_config[i] &= !(1u32 << bit);
        code(result::OK)
    }

    fn r_mem_slot(&self, c: &[u8], uap_addr: u16) -> Result<u16, u8> {
        let slot = u16_at(c, 1);
        if slot > R_MEM_SLOT_MAX {
            return Err(result::UNAUTHORIZED);
        }
        if !self.allowed(uap_addr, (slot as u32 / 128) * 8) {
            return Err(result::UNAUTHORIZED);
        }
        Ok(slot)
    }

    /// R_Mem_Data_Write: `[0x40][slot u16][pad][data...]`.
    fn r_mem_write(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.r_mem_slot(c, uap::R_MEM_DATA_WRITE) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        let data = &c[4..];
        if data.is_empty() || data.len() > self.p.r_mem_slot_max() {
            return code(result::FAIL);
        }
        if self.dev.r_mem_slots.contains_key(&slot) {
            return code(result::SLOT_NOT_EMPTY);
        }
        self.dev.r_mem_slots.insert(slot, data.to_vec());
        code(result::OK)
    }

    /// R_Mem_Data_Read: `[0x41][slot u16]` -> `[OK][pad 3][data...]`. An
    /// empty slot reads back as RESULT_OK with no data.
    fn r_mem_read(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.r_mem_slot(c, uap::R_MEM_DATA_READ) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        let mut f = vec![0u8; 3];
        if let Some(d) = self.dev.r_mem_slots.get(&slot) {
            f.extend_from_slice(d);
        }
        ok(&f)
    }

    fn r_mem_erase(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.r_mem_slot(c, uap::R_MEM_DATA_ERASE) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        self.dev.r_mem_slots.remove(&slot);
        code(result::OK)
    }

    /// Random_Value_Get: `[0x50][n]` -> `[OK][pad 3][n random bytes]`.
    fn random(&mut self, c: &[u8]) -> Vec<u8> {
        if !self.allowed(uap::RANDOM_VALUE_GET, 0) {
            return code(result::UNAUTHORIZED);
        }
        let mut f = vec![0u8; 3 + c[1] as usize];
        OsRng.fill_bytes(&mut f[3..]);
        ok(&f)
    }

    fn ecc_slot(&self, c: &[u8], uap_addr: u16) -> Result<u16, u8> {
        let slot = u16_at(c, 1);
        if slot > ECC_SLOT_MAX {
            return Err(result::UNAUTHORIZED);
        }
        if !self.allowed(uap_addr, (slot as u32 / 8) * 8) {
            return Err(result::UNAUTHORIZED);
        }
        Ok(slot)
    }

    /// ECC_Key_Generate: `[0x60][slot u16][curve]`.
    fn ecc_generate(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.ecc_slot(c, uap::ECC_KEY_GENERATE) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        let Some(curve) = CurveKind::from_wire_id(c[3]) else {
            return code(result::FAIL);
        };
        if self.dev.ecc_slots.contains_key(&slot) {
            return code(result::FAIL);
        }
        let private_key = match curve {
            CurveKind::P256 => P256Secret::random(&mut OsRng).to_bytes().to_vec(),
            CurveKind::Ed25519 => {
                let mut k = [0u8; 32];
                OsRng.fill_bytes(&mut k);
                k.to_vec()
            }
        };
        self.dev.ecc_slots.insert(
            slot,
            EccSlot {
                curve,
                origin: KeyOrigin::Generated,
                private_key,
            },
        );
        code(result::OK)
    }

    /// ECC_Key_Store: `[0x61][slot u16][curve][pad 12][k 32]`.
    fn ecc_store(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.ecc_slot(c, uap::ECC_KEY_STORE) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        let Some(curve) = CurveKind::from_wire_id(c[3]) else {
            return code(result::FAIL);
        };
        if self.dev.ecc_slots.contains_key(&slot) {
            return code(result::FAIL);
        }
        let k = &c[16..48];
        if curve == CurveKind::P256 && P256Secret::from_slice(k).is_err() {
            return code(result::FAIL);
        }
        self.dev.ecc_slots.insert(
            slot,
            EccSlot {
                curve,
                origin: KeyOrigin::Stored,
                private_key: k.to_vec(),
            },
        );
        code(result::OK)
    }

    /// ECC_Key_Read: `[0x62][slot u16]` ->
    /// `[OK][curve][origin][pad 13][pubkey (64 B P-256 X||Y, 32 B Ed25519)]`.
    fn ecc_read(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.ecc_slot(c, uap::ECC_KEY_READ) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        let Some(entry) = self.dev.ecc_slots.get(&slot) else {
            return code(result::INVALID_KEY);
        };
        let Some(public) = public_key(entry) else {
            return code(result::FAIL);
        };
        let mut f = vec![entry.curve.wire_id(), entry.origin.wire_id()];
        f.extend_from_slice(&[0u8; 13]);
        f.extend_from_slice(&public);
        ok(&f)
    }

    fn ecc_erase(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.ecc_slot(c, uap::ECC_KEY_ERASE) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        self.dev.ecc_slots.remove(&slot);
        code(result::OK)
    }

    /// ECDSA_Sign: `[0x70][slot u16][pad 13][hash 32]` -> `[OK][pad 15][r][s]`.
    /// The chip signs the 32-byte hash as given, with a random nonce.
    fn ecdsa_sign(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.ecc_slot(c, uap::ECDSA_SIGN) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        let Some(entry) = self.dev.ecc_slots.get(&slot) else {
            return code(result::INVALID_KEY);
        };
        if entry.curve != CurveKind::P256 {
            return code(result::INVALID_KEY);
        }
        let Ok(secret) = P256Secret::from_slice(&entry.private_key) else {
            return code(result::FAIL);
        };
        let key = P256Signing::from(&secret);
        let sig: P256Signature = match key.sign_prehash_with_rng(&mut OsRng, &c[16..48]) {
            Ok(s) => s,
            Err(_) => return code(result::FAIL),
        };
        let mut f = vec![0u8; 15];
        f.extend_from_slice(&sig.to_bytes());
        ok(&f)
    }

    /// EDDSA_Sign: `[0x71][slot u16][pad 13][msg...]` -> `[OK][pad 15][R][S]`.
    fn eddsa_sign(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = match self.ecc_slot(c, uap::EDDSA_SIGN) {
            Ok(s) => s,
            Err(e) => return code(e),
        };
        // An empty message is a valid size, but the ES firmware answers it
        // without a signature (after validating the slot).
        if c.len() == 16 && self.p.eddsa_empty_message_unsigned() {
            return code(result::OK);
        }
        let Some(entry) = self.dev.ecc_slots.get(&slot) else {
            return code(result::INVALID_KEY);
        };
        if entry.curve != CurveKind::Ed25519 {
            return code(result::INVALID_KEY);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&entry.private_key);
        let mut f = vec![0u8; 15];
        f.extend_from_slice(&ed25519_sign_hedged(&seed, &c[16..]));
        ok(&f)
    }

    fn mcounter_index(&self, c: &[u8], uap_addr: u16) -> Result<u16, u8> {
        let idx = u16_at(c, 1);
        if idx > MCOUNTER_MAX {
            return Err(result::UNAUTHORIZED);
        }
        if !self.allowed(uap_addr, (idx as u32 / 4) * 8) {
            return Err(result::UNAUTHORIZED);
        }
        Ok(idx)
    }

    /// MCounter_Init: `[0x80][index u16][pad][value u32]`.
    fn mcounter_init(&mut self, c: &[u8]) -> Vec<u8> {
        let idx = match self.mcounter_index(c, uap::MCOUNTER_INIT) {
            Ok(i) => i,
            Err(e) => return code(e),
        };
        let v = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        if v > MCOUNTER_VALUE_MAX {
            return code(result::FAIL);
        }
        self.dev.mcounters.insert(idx, v);
        code(result::OK)
    }

    /// MCounter_Update: `[0x81][index u16]` decrements by one.
    fn mcounter_update(&mut self, c: &[u8]) -> Vec<u8> {
        let idx = match self.mcounter_index(c, uap::MCOUNTER_UPDATE) {
            Ok(i) => i,
            Err(e) => return code(e),
        };
        match self.dev.mcounters.get_mut(&idx) {
            None => code(result::COUNTER_INVALID),
            Some(0) => code(result::UPDATE_ERR),
            Some(v) => {
                *v -= 1;
                code(result::OK)
            }
        }
    }

    /// MCounter_Get: `[0x82][index u16]` -> `[OK][pad 3][value u32]`.
    fn mcounter_get(&mut self, c: &[u8]) -> Vec<u8> {
        let idx = match self.mcounter_index(c, uap::MCOUNTER_GET) {
            Ok(i) => i,
            Err(e) => return code(e),
        };
        match self.dev.mcounters.get(&idx) {
            None => code(result::COUNTER_INVALID),
            Some(v) => {
                let mut f = vec![0u8; 3];
                f.extend_from_slice(&v.to_le_bytes());
                ok(&f)
            }
        }
    }

    /// MAC_And_Destroy: `[0x90][slot u16][pad][data_in 32]` ->
    /// `[OK][pad 3][data_out 32]`.
    ///
    /// As in ts-tvl: with `s` the slot content, the slot is overwritten
    /// with `s' = F1(data_in || slot)` and the output is
    /// `F2(s || s' || slot)`, where F1/F2 are KMAC256 under the device keys
    /// K1/K2. The output therefore depends only on the previous and current
    /// inputs, which is what the bench chip shows.
    fn mac_and_destroy(&mut self, c: &[u8]) -> Vec<u8> {
        let slot = u16_at(c, 1);
        if slot > MACANDD_SLOT_MAX {
            return code(result::UNAUTHORIZED);
        }
        if !self.allowed(uap::MAC_AND_DESTROY, (slot as u32 / 32) * 8) {
            return code(result::UNAUTHORIZED);
        }
        let slot_byte = [slot as u8];
        let s = self
            .dev
            .macandd_slots
            .get(&slot)
            .copied()
            .unwrap_or([0xff; 32]);
        let s_new = kmac256(&self.dev.macandd_keys[0], &[&c[4..36], &slot_byte]);
        self.dev.macandd_slots.insert(slot, s_new);
        let out = kmac256(&self.dev.macandd_keys[1], &[&s, &s_new, &slot_byte]);
        let mut f = vec![0u8; 3];
        f.extend_from_slice(&out);
        ok(&f)
    }
}

fn kmac256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Kmac::v256(key, MACANDD_CUSTOM);
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// Public key bytes for a slot as ECC_Key_Read returns them.
pub fn public_key(entry: &EccSlot) -> Option<Vec<u8>> {
    match entry.curve {
        CurveKind::P256 => {
            let secret = P256Secret::from_slice(&entry.private_key).ok()?;
            let point = secret.public_key().to_encoded_point(false);
            Some(point.as_bytes()[1..65].to_vec())
        }
        CurveKind::Ed25519 => {
            let seed: [u8; 32] = entry.private_key.as_slice().try_into().ok()?;
            Some(
                Ed25519Signing::from_bytes(&seed)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            )
        }
    }
}

/// Ed25519 signature with a hedged nonce. The result verifies as a normal
/// RFC 8032 signature, but like the chip's it is not deterministic: the
/// nonce mixes 32 fresh random bytes into the usual prefix || message hash.
pub fn ed25519_sign_hedged(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let h = Sha512::digest(seed);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&h[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let a = Scalar::from_bytes_mod_order(a_bytes);
    let public = EdwardsPoint::mul_base(&a).compress();

    let mut z = [0u8; 32];
    OsRng.fill_bytes(&mut z);
    let r = Scalar::from_hash(
        Sha512::new()
            .chain_update(z)
            .chain_update(&h[32..])
            .chain_update(msg),
    );
    let r_point = EdwardsPoint::mul_base(&r).compress();
    let k = Scalar::from_hash(
        Sha512::new()
            .chain_update(r_point.as_bytes())
            .chain_update(public.as_bytes())
            .chain_update(msg),
    );
    let s = r + k * a;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r_point.as_bytes());
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::Store;
    use ed25519_dalek::{Signature as EdSignature, Verifier};
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

    fn run(dev: &mut Device, p: Personality, cmd: &[u8]) -> Vec<u8> {
        match dispatch(dev, p, 0, cmd) {
            L3Outcome::Result(r) => r,
            L3Outcome::GenErr => vec![],
        }
    }

    fn es(dev: &mut Device, cmd: &[u8]) -> Vec<u8> {
        run(dev, Personality::Es012, cmd)
    }

    #[test]
    fn unknown_ids_are_invalid_cmd() {
        let mut s = Store::fresh();
        for id in [0x00, 0x02, 0x13, 0x91, 0xa0, 0xa5, 0xff] {
            assert_eq!(es(&mut s.device, &[id, 0, 0, 0]), vec![result::INVALID_CMD]);
        }
    }

    #[test]
    fn r_mem_semantics() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        assert_eq!(es(d, &[0x41, 0xff, 0x01]), vec![result::OK, 0, 0, 0]);
        assert_eq!(es(d, &[0x40, 0xff, 0x01, 0, 0xaa]), vec![result::OK]);
        assert_eq!(
            es(d, &[0x40, 0xff, 0x01, 0, 0xbb]),
            vec![result::SLOT_NOT_EMPTY]
        );
        assert_eq!(es(d, &[0x41, 0xff, 0x01]), vec![result::OK, 0, 0, 0, 0xaa]);
        assert_eq!(es(d, &[0x42, 0xff, 0x01]), vec![result::OK]);
        assert_eq!(es(d, &[0x41, 0x00, 0x02]), vec![result::UNAUTHORIZED]);
        let mut big = vec![0x40, 0x00, 0x00, 0x00];
        big.extend(vec![1u8; 445]);
        assert_eq!(es(d, &big), vec![result::FAIL]);
        assert_eq!(run(d, Personality::Fw220, &big), vec![result::OK]);
    }

    #[test]
    fn mcounter_semantics() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        assert_eq!(es(d, &[0x82, 15, 0]), vec![result::COUNTER_INVALID]);
        assert_eq!(es(d, &[0x81, 15, 0]), vec![result::COUNTER_INVALID]);
        assert_eq!(es(d, &[0x80, 15, 0, 0, 1, 0, 0, 0]), vec![result::OK]);
        assert_eq!(es(d, &[0x81, 15, 0]), vec![result::OK]);
        assert_eq!(es(d, &[0x81, 15, 0]), vec![result::UPDATE_ERR]);
        assert_eq!(es(d, &[0x82, 15, 0]), vec![result::OK, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            es(d, &[0x80, 15, 0, 0, 0xff, 0xff, 0xff, 0xff]),
            vec![result::FAIL]
        );
        assert_eq!(es(d, &[0x82, 16, 0]), vec![result::UNAUTHORIZED]);
    }

    #[test]
    fn ecc_semantics_and_signatures_verify() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        assert_eq!(es(d, &[0x62, 31, 0]), vec![result::INVALID_KEY]);
        assert_eq!(es(d, &[0x63, 31, 0]), vec![result::OK]);
        assert_eq!(es(d, &[0x60, 31, 0, 1]), vec![result::OK]);
        assert_eq!(es(d, &[0x60, 31, 0, 1]), vec![result::FAIL]);
        assert_eq!(es(d, &[0x60, 32, 0, 1]), vec![result::UNAUTHORIZED]);
        assert_eq!(es(d, &[0x60, 30, 0, 3]), vec![result::FAIL]);
        let r = es(d, &[0x62, 31, 0]);
        assert_eq!(r.len(), 80);
        assert_eq!(&r[1..3], &[1, 1]);
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&r[16..80]);
        let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let mut cmd = vec![0x70, 31, 0];
        cmd.extend_from_slice(&[0u8; 13]);
        cmd.extend_from_slice(&[0x5a; 32]);
        let s1 = es(d, &cmd);
        let s2 = es(d, &cmd);
        assert_eq!(s1.len(), 80);
        assert_ne!(s1, s2, "ECDSA must use a random nonce");
        let sig = P256Signature::from_slice(&s1[16..80]).unwrap();
        vk.verify_prehash(&[0x5a; 32], &sig).unwrap();
        // EdDSA on a P-256 slot
        let mut ed = vec![0x71, 31, 0];
        ed.extend_from_slice(&[0u8; 13]);
        ed.push(1);
        assert_eq!(es(d, &ed), vec![result::INVALID_KEY]);
    }

    #[test]
    fn eddsa_hedged_signature_verifies() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        let seed = [7u8; 32];
        let mut store = vec![0x61, 3, 0, 2];
        store.extend_from_slice(&[0u8; 12]);
        store.extend_from_slice(&seed);
        assert_eq!(es(d, &store), vec![result::OK]);
        let mut cmd = vec![0x71, 3, 0];
        cmd.extend_from_slice(&[0u8; 13]);
        cmd.extend_from_slice(b"hello");
        let r1 = es(d, &cmd);
        let r2 = es(d, &cmd);
        assert_ne!(r1, r2);
        let vk = Ed25519Signing::from_bytes(&seed).verifying_key();
        let sig = EdSignature::from_slice(&r1[16..80]).unwrap();
        vk.verify(b"hello", &sig).unwrap();
        // Empty message: ES firmware returns OK without a signature.
        assert_eq!(es(d, &cmd[..16]), vec![result::OK]);
        assert_eq!(run(d, Personality::Fw220, &cmd[..16]).len(), 80);
    }

    #[test]
    fn mac_and_destroy_properties() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        let md = |d: &mut Device, slot: u8, b: u8| {
            let mut c = vec![0x90, slot, 0, 0];
            c.extend_from_slice(&[b; 32]);
            es(d, &c)
        };
        md(d, 127, 0xa1);
        let o2 = md(d, 127, 0xa1);
        let o3 = md(d, 127, 0xa1);
        assert_eq!(o2, o3);
        md(d, 127, 0xa1);
        let ab1 = md(d, 127, 0xb2);
        md(d, 127, 0xc3);
        md(d, 127, 0xa1);
        let ab2 = md(d, 127, 0xb2);
        assert_eq!(ab1, ab2);
        md(d, 126, 0xa1);
        assert_ne!(md(d, 126, 0xb2), ab1);
        assert_eq!(md(d, 128, 0xa1), vec![result::UNAUTHORIZED]);
    }

    #[test]
    fn size_handling_per_personality() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        // ES: ECDSA with a wrong size answers OK with no data.
        assert_eq!(es(d, &[0x70; 47]), vec![result::OK]);
        // ES: Random_Value_Get with an extra byte still executes.
        assert_eq!(es(d, &[0x50, 4, 0]).len(), 8);
        assert_eq!(es(d, &[0x50]), vec![result::FAIL]);
        // 2.x: L2 GEN_ERR.
        assert_eq!(
            dispatch(d, Personality::Fw220, 0, &[0x50, 4, 0]),
            L3Outcome::GenErr
        );
    }

    #[test]
    fn uap_restricts_by_pairing_slot() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        // Allow only SH1 to ping.
        d.r_config[0x100 / 4] = 0xffff_ff02;
        assert_eq!(
            run(d, Personality::Es012, &[0x01, 9]),
            vec![result::UNAUTHORIZED]
        );
        assert_eq!(
            dispatch(d, Personality::Es012, 1, &[0x01, 9]),
            L3Outcome::Result(vec![result::OK, 9])
        );
    }

    #[test]
    fn config_read_write() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        assert_eq!(es(d, &[0x21, 0x02, 0x00]), vec![result::FAIL]);
        assert_eq!(es(d, &[0x21, 0x00, 0x02]), vec![result::UNAUTHORIZED]);
        assert_eq!(
            es(d, &[0x21, 0xfc, 0x00]),
            vec![result::OK, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            es(d, &[0x20, 0x04, 0x00, 0, 0x78, 0x56, 0x34, 0x12]),
            vec![result::OK]
        );
        assert_eq!(
            es(d, &[0x20, 0x04, 0x00, 0, 0, 0, 0, 0]),
            vec![result::FAIL]
        );
        assert_eq!(es(d, &[0x22]), vec![result::OK]);
        assert_eq!(es(d, &[0x30, 0x04, 0x00, 3]), vec![result::OK]);
        assert_eq!(
            es(d, &[0x31, 0x04, 0x00]),
            vec![result::OK, 0, 0, 0, 0xf7, 0xff, 0xff, 0xff]
        );
        assert_eq!(es(d, &[0x30, 0x04, 0x00, 32]), vec![result::FAIL]);
    }

    #[test]
    fn pairing_keys() {
        let mut s = Store::fresh();
        let d = &mut s.device;
        assert_eq!(es(d, &[0x11, 1, 0]), vec![result::SLOT_EMPTY]);
        assert_eq!(es(d, &[0x11, 4, 0]), vec![result::UNAUTHORIZED]);
        assert_eq!(es(d, &[0x12, 1, 0]), vec![result::FAIL]);
        let mut w = vec![0x10, 1, 0, 0];
        w.extend_from_slice(&[9u8; 32]);
        assert_eq!(es(d, &w), vec![result::OK]);
        assert_eq!(es(d, &w), vec![result::FAIL]);
        assert_eq!(es(d, &[0x12, 1, 0]), vec![result::OK]);
        assert_eq!(es(d, &[0x11, 1, 0]), vec![result::SLOT_INVALID]);
    }
}
