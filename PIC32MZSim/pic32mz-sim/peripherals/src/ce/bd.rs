/* ce/bd.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of PIC32MZSim.
 *
 * PIC32MZSim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * PIC32MZSim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

//! `bufferDescriptor` and `securityAssociation` bit layouts. The C
//! types live in `wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h`; we
//! mirror them here so the simulator can parse what the wolfSSL driver
//! writes. Bit-field ordering is GCC/MIPS-LE: fields are allocated
//! starting at the LSB in declaration order.

use anyhow::Result;
use pic32mz_sim_core::MemBus;

/// `bdCtrl`: 32 bits.
///
///   bit 0..15  BUFLEN
///   bit 16     CBD_INT_EN
///   bit 17     PKT_INT_EN
///   bit 18     LIFM
///   bit 19     LAST_BD
///   bit 20     CRDMA_EN
///   bit 21     UPD_RES
///   bit 22     SA_FETCH_EN
///   bit 23..30 SEC_CODE
///   bit 31     DESC_EN
#[derive(Debug, Default, Clone, Copy)]
pub struct BdCtrl(pub u32);

impl BdCtrl {
    pub fn buflen(self) -> u32 { self.0 & 0xFFFF }
    pub fn pkt_int_en(self) -> bool { (self.0 >> 17) & 1 != 0 }
    pub fn lifm(self) -> bool { (self.0 >> 18) & 1 != 0 }
    pub fn last_bd(self) -> bool { (self.0 >> 19) & 1 != 0 }
    pub fn sa_fetch_en(self) -> bool { (self.0 >> 22) & 1 != 0 }
    pub fn desc_en(self) -> bool { (self.0 >> 31) & 1 != 0 }

    pub fn set_buflen(&mut self, v: u32) { self.0 = (self.0 & !0xFFFF) | (v & 0xFFFF); }
    pub fn set_bit(&mut self, b: u32) { self.0 |= 1 << b; }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct BufferDescriptor {
    pub bd_ctrl: BdCtrl,
    pub sa_addr: u32,
    pub srcaddr: u32,
    pub dstaddr: u32,
    pub nxtptr: u32,
    pub updptr: u32,
    pub msglen: u32,
    pub encoff: u32,
}

impl BufferDescriptor {
    pub const SIZE: usize = 32;

    pub fn read_phys(mem: &mut dyn MemBus, paddr: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        mem.read_phys(paddr, &mut buf)?;
        Ok(Self {
            bd_ctrl: BdCtrl(u32::from_le_bytes(buf[0..4].try_into().unwrap())),
            sa_addr: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            srcaddr: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            dstaddr: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            nxtptr: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            updptr: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            msglen: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
            encoff: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
        })
    }

    pub fn write_phys(&self, mem: &mut dyn MemBus, paddr: u64) -> Result<()> {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.bd_ctrl.0.to_le_bytes());
        buf[4..8].copy_from_slice(&self.sa_addr.to_le_bytes());
        buf[8..12].copy_from_slice(&self.srcaddr.to_le_bytes());
        buf[12..16].copy_from_slice(&self.dstaddr.to_le_bytes());
        buf[16..20].copy_from_slice(&self.nxtptr.to_le_bytes());
        buf[20..24].copy_from_slice(&self.updptr.to_le_bytes());
        buf[24..28].copy_from_slice(&self.msglen.to_le_bytes());
        buf[28..32].copy_from_slice(&self.encoff.to_le_bytes());
        mem.write_phys(paddr, &buf)
    }

    pub fn buflen(&self) -> u32 { self.bd_ctrl.buflen() }
    pub fn sa_fetch_enabled(&self) -> bool { self.bd_ctrl.sa_fetch_en() }
    pub fn desc_enabled(&self) -> bool { self.bd_ctrl.desc_en() }
    pub fn last_bd(&self) -> bool { self.bd_ctrl.last_bd() }
    pub fn lifm(&self) -> bool { self.bd_ctrl.lifm() }

    pub fn set_buflen(&mut self, v: u32) { self.bd_ctrl.set_buflen(v); }
    pub fn set_pkt_int_en(&mut self) { self.bd_ctrl.set_bit(17); }
    pub fn set_lifm(&mut self) { self.bd_ctrl.set_bit(18); }
    pub fn set_last_bd(&mut self) { self.bd_ctrl.set_bit(19); }
    pub fn set_sa_fetch_en(&mut self) { self.bd_ctrl.set_bit(22); }
    pub fn set_desc_en(&mut self) { self.bd_ctrl.set_bit(31); }
}

/// `saCtrl`: 32 bits.
///
///   bit 0..3   CRYPTOALGO
///   bit 4..6   MULTITASK
///   bit 7..8   KEYSIZE
///   bit 9      ENCTYPE   (1=encrypt, 0=decrypt)
///   bit 10..16 ALGO
///   bit 17..19 reserved
///   bit 20     FLAGS
///   bit 21     FB        (first block)
///   bit 22     LOADIV
///   bit 23     LNC       (load new key)
///   bit 24     IRFLAG
///   bit 25     ICVONLY
///   bit 26     OR_EN
///   bit 27     NO_RX
///   bit 28     reserved
///   bit 29     VERIFY
///   bit 30..31 reserved
#[derive(Debug, Default, Clone, Copy)]
pub struct SaCtrl {
    pub cryptoalgo: u8,
    pub multitask: u8,
    pub keysize: u8,
    pub enctype: u8,
    pub algo: u8,
    pub flags: u8,
    pub fb: u8,
    pub loadiv: u8,
    pub lnc: u8,
    pub irflag: u8,
    pub icvonly: u8,
    pub or_en: u8,
    pub no_rx: u8,
    pub verify: u8,
}

impl SaCtrl {
    pub fn from_u32(v: u32) -> Self {
        Self {
            cryptoalgo: ((v >> 0) & 0xF) as u8,
            multitask: ((v >> 4) & 0x7) as u8,
            keysize: ((v >> 7) & 0x3) as u8,
            enctype: ((v >> 9) & 0x1) as u8,
            algo: ((v >> 10) & 0x7F) as u8,
            flags: ((v >> 20) & 0x1) as u8,
            fb: ((v >> 21) & 0x1) as u8,
            loadiv: ((v >> 22) & 0x1) as u8,
            lnc: ((v >> 23) & 0x1) as u8,
            irflag: ((v >> 24) & 0x1) as u8,
            icvonly: ((v >> 25) & 0x1) as u8,
            or_en: ((v >> 26) & 0x1) as u8,
            no_rx: ((v >> 27) & 0x1) as u8,
            verify: ((v >> 29) & 0x1) as u8,
        }
    }
    pub fn to_u32(self) -> u32 {
        ((self.cryptoalgo as u32) & 0xF)
            | (((self.multitask as u32) & 0x7) << 4)
            | (((self.keysize as u32) & 0x3) << 7)
            | (((self.enctype as u32) & 0x1) << 9)
            | (((self.algo as u32) & 0x7F) << 10)
            | (((self.flags as u32) & 0x1) << 20)
            | (((self.fb as u32) & 0x1) << 21)
            | (((self.loadiv as u32) & 0x1) << 22)
            | (((self.lnc as u32) & 0x1) << 23)
            | (((self.irflag as u32) & 0x1) << 24)
            | (((self.icvonly as u32) & 0x1) << 25)
            | (((self.or_en as u32) & 0x1) << 26)
            | (((self.no_rx as u32) & 0x1) << 27)
            | (((self.verify as u32) & 0x1) << 29)
    }
}

#[derive(Debug, Default, Clone)]
pub struct SecurityAssociation {
    pub ctrl: SaCtrl,
    pub authkey: [u32; 8],
    pub enckey: [u32; 8],
    pub authiv: [u32; 8],
    pub enciv: [u32; 4],
}

impl SecurityAssociation {
    pub const SIZE: usize = 4 + 32 + 32 + 32 + 16;

    pub fn read_phys(mem: &mut dyn MemBus, paddr: u64) -> Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        mem.read_phys(paddr, &mut buf)?;
        let mut sa = Self::default();
        sa.ctrl = SaCtrl::from_u32(u32::from_le_bytes(buf[0..4].try_into().unwrap()));
        for i in 0..8 {
            let off = 4 + i * 4;
            sa.authkey[i] = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        }
        for i in 0..8 {
            let off = 36 + i * 4;
            sa.enckey[i] = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        }
        for i in 0..8 {
            let off = 68 + i * 4;
            sa.authiv[i] = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        }
        for i in 0..4 {
            let off = 100 + i * 4;
            sa.enciv[i] = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        }
        Ok(sa)
    }

    pub fn write_phys(&self, mem: &mut dyn MemBus, paddr: u64) -> Result<()> {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.ctrl.to_u32().to_le_bytes());
        for i in 0..8 {
            let off = 4 + i * 4;
            buf[off..off + 4].copy_from_slice(&self.authkey[i].to_le_bytes());
        }
        for i in 0..8 {
            let off = 36 + i * 4;
            buf[off..off + 4].copy_from_slice(&self.enckey[i].to_le_bytes());
        }
        for i in 0..8 {
            let off = 68 + i * 4;
            buf[off..off + 4].copy_from_slice(&self.authiv[i].to_le_bytes());
        }
        for i in 0..4 {
            let off = 100 + i * 4;
            buf[off..off + 4].copy_from_slice(&self.enciv[i].to_le_bytes());
        }
        mem.write_phys(paddr, &buf)
    }

    /// Rebuild the original cipher-key byte array. The wolfSSL driver
    /// stages the key into `SA_ENCKEY` (right-justified) by running
    /// `ByteReverseWords` over each 32-bit word; on a little-endian
    /// host that puts the natural big-endian key value into a u32,
    /// which is stored little-endian to memory. Reading the word back
    /// LE-form recovers the u32 holding the big-endian key view, so
    /// emitting it via `to_be_bytes` yields the original key bytes.
    pub fn cipher_key(&self, key_len_bytes: usize) -> Vec<u8> {
        let words = key_len_bytes / 4;
        let start = self.enckey.len() - words;
        let mut out = Vec::with_capacity(key_len_bytes);
        for i in 0..words {
            out.extend_from_slice(&self.enckey[start + i].to_be_bytes());
        }
        out
    }

    pub fn cipher_iv(&self, iv_len_bytes: usize) -> Vec<u8> {
        let words = iv_len_bytes / 4;
        let start = self.enciv.len() - words;
        let mut out = Vec::with_capacity(iv_len_bytes);
        for i in 0..words {
            out.extend_from_slice(&self.enciv[start + i].to_be_bytes());
        }
        out
    }

    /// SHA initial state lives in AUTHIV right-justified after the
    /// driver's `ByteReverseWords` pass. `state_words` is 5 for SHA-1,
    /// 8 for SHA-256, 4 for MD5. The simulator does not actually feed
    /// this back into RustCrypto (the digest implementation has its
    /// own fixed IV table); the helper is exposed so a future
    /// streaming-hash path can chain partial digests through the
    /// firmware-supplied AUTHIV.
    pub fn hash_iv(&self, state_words: usize) -> Vec<u32> {
        let start = self.authiv.len() - state_words;
        (0..state_words).map(|i| self.authiv[start + i]).collect()
    }
}
