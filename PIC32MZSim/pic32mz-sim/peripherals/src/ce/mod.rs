/* ce/mod.rs
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

//! PIC32MZ Crypto Engine peripheral. The engine sits at physical base
//! 0x1F8E_0000 (KSEG1 alias 0xBF8E_0000). It is fed by a DMA descriptor
//! chain (`bufferDescriptor`) whose first entry's physical address is
//! written to `CEBDPADDR`; each descriptor also points at a
//! `securityAssociation` containing the algorithm selector, key, and
//! IV / initial hash state. The CECON.START write kicks the engine,
//! which then walks the chain, executes each operation, writes the
//! result back to RAM via the descriptor's DSTADDR or UPDPTR, and
//! asserts `CEINTSRC.PKTIF` on completion.
//!
//! We mirror that flow synchronously inside the MMIO callback: the
//! firmware's store to CECON drives `start_dma` which reads the BD
//! + SA from emulator RAM, dispatches to the appropriate RustCrypto
//! primitive, writes the output back, and sets PKTIF. The firmware's
//! subsequent polling read of CEINTSRC sees PKTIF asserted immediately.

mod bd;
mod algo;
mod polling;

pub use bd::{BufferDescriptor, SaCtrl, SecurityAssociation};

use pic32mz_sim_core::{MemBus, Peripheral};
use std::sync::{Arc, Mutex};

/// Register byte offsets within the CE 4 KiB window. Each register
/// occupies 16 bytes for the PIC32 atomic SET/CLR/INV alias quartet
/// (base / SET / CLR / INV at +0/+4/+8/+0xC).
const CECON_OFF: u32 = 0x000;
const CESTAT_OFF: u32 = 0x010;
const CEINTSRC_OFF: u32 = 0x020;
const CEINTEN_OFF: u32 = 0x030;
const CEBDPADDR_OFF: u32 = 0x040;
const CEPOLLCON_OFF: u32 = 0x050;

/// CECON.START - bit 0, kicks off DMA on a CECON write.
const CECON_START: u32 = 1 << 0;
/// CECON.SWRST - bit 6, software reset of the engine.
const CECON_SWRST: u32 = 1 << 6;
/// CECON.OUT_SWAP - bit 7, byte-swap output words on the way out. The
/// wolfSSL port writes 0xA5 (with this set) on EF and 0x25 (without)
/// on EC. EC firmware byte-reverses the output in software instead.
const CECON_OUT_SWAP: u32 = 1 << 7;
/// CECON polling-mode trigger - bit 1, set in addition to START, is
/// what differentiates the streaming-large-hash arm (CECON = 0xA7 /
/// 0x27) from the one-shot single-BD path (CECON = 0xA5 / 0x25). Both
/// share bits 0 (START), 2 and 5; only bit 1 toggles between the two
/// flows on the wolfSSL `reset_engine` vs `Pic32Crypto` write.
const CECON_POLLING: u32 = 1 << 1;

/// CEINTSRC bits the engine reports / the firmware clears with `0xF`.
const CEINTSRC_PKTIF: u32 = 1 << 1;
const CEINTSRC_ALL: u32 = 0x0F;

/// Maximum chain length we will follow. Real silicon caps the BD chain
/// at the table the DMA channel was configured for; we just want a
/// sanity bound so a buggy NXTPTR loop does not hang the test.
const MAX_BD_CHAIN: usize = 64;

pub struct CryptoEngine {
    cecon: u32,
    cestat: u32,
    ceintsrc: u32,
    ceinten: u32,
    cebdpaddr: u32,
    cepollcon: u32,
    /// EC silicon cannot byte-swap output in hardware. When this flag
    /// is set we ignore CECON.OUT_SWAP at execution time so a faulty
    /// firmware bit pattern does not silently flip output endianness.
    pub no_out_swap: bool,
    /// Polling-mode (LARGE_HASH) tick handle. `Some((idx, flag))`
    /// when armed - `idx` is the global-tick registry index to
    /// disarm; `flag` flips to true when the chain's LAST_BD has
    /// committed the final digest.
    polling: Option<(usize, Arc<Mutex<bool>>)>,
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self {
            cecon: 0,
            cestat: 0,
            ceintsrc: 0,
            ceinten: 0,
            cebdpaddr: 0,
            cepollcon: 0,
            no_out_swap: false,
            polling: None,
        }
    }

    fn disarm_polling(&mut self) {
        if let Some((idx, _)) = self.polling.take() {
            polling::disarm(idx);
        }
    }

    pub fn for_ec() -> Self {
        let mut e = Self::new();
        e.no_out_swap = true;
        e
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn atomic_op(current: u32, lane: u32, value: u32) -> u32 {
    match lane {
        0 => value,
        1 => current | value,
        2 => current & !value,
        3 => current ^ value,
        _ => current,
    }
}

fn split_atomic(offset: u32, base: u32) -> Option<u32> {
    let delta = offset.wrapping_sub(base);
    if delta < 16 {
        Some(delta >> 2)
    } else {
        None
    }
}

impl Peripheral for CryptoEngine {
    fn name(&self) -> &str {
        "ce"
    }

    fn read(&mut self, offset: u32, _size: u8) -> u32 {
        if let Some(lane) = split_atomic(offset, CECON_OFF) {
            if lane == 0 { return self.cecon; }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, CESTAT_OFF) {
            if lane == 0 { return self.cestat; }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, CEINTSRC_OFF) {
            if lane == 0 { return self.ceintsrc; }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, CEINTEN_OFF) {
            if lane == 0 { return self.ceinten; }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, CEBDPADDR_OFF) {
            if lane == 0 { return self.cebdpaddr; }
            return 0;
        }
        if let Some(lane) = split_atomic(offset, CEPOLLCON_OFF) {
            if lane == 0 { return self.cepollcon; }
            return 0;
        }
        0
    }

    fn write(&mut self, offset: u32, _size: u8, value: u32, mem: &mut dyn MemBus) {
        if let Some(lane) = split_atomic(offset, CECON_OFF) {
            let new = atomic_op(self.cecon, lane, value);
            self.cecon = new;
            if new & CECON_SWRST != 0 {
                // Real silicon clears the CECON register when reset
                // completes; the wolfSSL driver spins `while (CECON);`
                // so we have to do the same dance.
                self.cecon = 0;
                self.cestat = 0;
                self.ceintsrc = 0;
                self.cebdpaddr = 0;
                self.disarm_polling();
                return;
            }
            if new & CECON_POLLING != 0 && new & CECON_START != 0 {
                // Polling / streaming-large-hash entry. `reset_engine`
                // in wolfSSL writes 0xA7 (EF) or 0x27 (EC) after
                // setting up the BD ring. We register a tick callback
                // that walks the BD chain on every TB boundary and
                // processes any BD with DESC_EN=1.
                let out_swap = !self.no_out_swap && (new & CECON_OUT_SWAP != 0);
                self.disarm_polling();
                match polling::arm(self.cebdpaddr, out_swap, mem) {
                    Ok((idx, flag)) => {
                        self.polling = Some((idx, flag));
                        self.cecon &= !CECON_START;
                    }
                    Err(err) => {
                        log::error!("CE polling-mode arm failed: {err}");
                        self.cestat = (self.cestat & !0xF) | 0x1;
                        self.ceintsrc |= CEINTSRC_PKTIF;
                        self.cecon &= !CECON_START;
                    }
                }
                return;
            }
            if new & CECON_START != 0 {
                let out_swap = !self.no_out_swap && (new & CECON_OUT_SWAP != 0);
                match self.run_chain(out_swap, mem) {
                    Ok(()) => {
                        self.ceintsrc |= CEINTSRC_PKTIF;
                    }
                    Err(err) => {
                        log::error!("CE chain execution failed: {err}");
                        // Set CESTAT.ERROP (low nybble, bits 0..3 per
                        // the stub header's `__CESTATbits_t` overlay
                        // and the wolfSSL driver's CESTATbits.ERROP
                        // read in pic32mz-crypt.c:238). Any non-zero
                        // value makes the driver return ASYNC_OP_E.
                        self.cestat = (self.cestat & !0xF) | 0x1;
                        self.ceintsrc |= CEINTSRC_PKTIF;
                    }
                }
                // START is auto-clearing on real silicon once DMA is
                // launched. Clearing it here keeps the firmware's
                // post-completion CECON reads stable.
                self.cecon &= !CECON_START;
            }
            return;
        }
        if let Some(lane) = split_atomic(offset, CESTAT_OFF) {
            self.cestat = atomic_op(self.cestat, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, CEINTSRC_OFF) {
            // CEINTSRC bits are write-1-to-clear on real silicon. The
            // wolfSSL driver writes 0xF to clear all four flags.
            if lane == 0 {
                self.ceintsrc &= !(value & CEINTSRC_ALL);
            } else {
                self.ceintsrc = atomic_op(self.ceintsrc, lane, value);
            }
            return;
        }
        if let Some(lane) = split_atomic(offset, CEINTEN_OFF) {
            self.ceinten = atomic_op(self.ceinten, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, CEBDPADDR_OFF) {
            self.cebdpaddr = atomic_op(self.cebdpaddr, lane, value);
            return;
        }
        if let Some(lane) = split_atomic(offset, CEPOLLCON_OFF) {
            self.cepollcon = atomic_op(self.cepollcon, lane, value);
            return;
        }
    }
}

impl CryptoEngine {
    /// Walk the BD chain from `CEBDPADDR`, execute each, write results
    /// to RAM. Stops when a BD has `LAST_BD` set or after MAX_BD_CHAIN
    /// iterations.
    fn run_chain(&mut self, out_swap: bool, mem: &mut dyn MemBus) -> anyhow::Result<()> {
        let mut bd_addr = self.cebdpaddr as u64;
        for _ in 0..MAX_BD_CHAIN {
            let bd = BufferDescriptor::read_phys(mem, bd_addr)?;
            log::debug!("CE BD @ paddr 0x{:08x}: {:?}", bd_addr, bd);
            if bd_addr != 0 && std::env::var("PIC32MZ_SIM_TRACE_BD").is_ok() {
                eprintln!("[ce-bd] @ 0x{:08x} {:?}", bd_addr, bd);
            }
            if !bd.desc_enabled() {
                anyhow::bail!(
                    "BD at 0x{bd_addr:08x} has DESC_EN=0 (BD_CTRL=0x{:08x} sa=0x{:08x} src=0x{:08x} dst=0x{:08x} upd=0x{:08x} msglen={})",
                    bd.bd_ctrl.0, bd.sa_addr, bd.srcaddr, bd.dstaddr, bd.updptr, bd.msglen
                );
            }
            let sa = if bd.sa_fetch_enabled() {
                let sa = SecurityAssociation::read_phys(mem, bd.sa_addr as u64)?;
                log::debug!("CE SA @ paddr 0x{:08x}: {:?}", bd.sa_addr, sa);
                if std::env::var("PIC32MZ_SIM_TRACE_BD").is_ok() {
                    eprintln!("[ce-sa] @ 0x{:08x} {:?}", bd.sa_addr, sa);
                }
                sa
            } else {
                anyhow::bail!("BD at 0x{bd_addr:08x} has SA_FETCH_EN=0 - unsupported");
            };

            algo::execute(&sa, &bd, out_swap, mem)?;

            if bd.last_bd() {
                break;
            }
            if bd.nxtptr == 0 || bd.nxtptr as u64 == bd_addr {
                break;
            }
            bd_addr = bd.nxtptr as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pic32mz_sim_core::InMemoryBus;

    /// AES-128 ECB FIPS-197 vector through the full BD+SA path.
    ///   key = 2b7e1516 28aed2a6 abf71588 09cf4f3c
    ///   pt  = 6bc1bee2 2e409f96 e93d7e11 7393172a
    ///   ct  = 3ad77bb4 0d7a3660 a89ecaf3 2466ef97
    #[test]
    fn aes128_ecb_round_trip_via_chain() {
        let mut mem = InMemoryBus::new();

        // Place SA at 0x10000, BD at 0x10200, input at 0x10400, output at 0x10600.
        let sa_addr = 0x10000u64;
        let bd_addr = 0x10200u64;
        let in_addr = 0x10400u64;
        let out_addr = 0x10600u64;

        let mut sa = SecurityAssociation::default();
        // ALGO = AES (0b100 = 0x04), CRYPTOALGO = RECB (0b1000),
        // KEYSIZE = 128 (0b00), ENCTYPE = encrypt (1), FB=1, LNC=1.
        sa.ctrl.algo = 0b0000100;
        sa.ctrl.cryptoalgo = 0b1000;
        sa.ctrl.keysize = 0b00;
        sa.ctrl.enctype = 1;
        sa.ctrl.fb = 1;
        sa.ctrl.lnc = 1;
        // Key, right-justified. The wolfSSL driver writes the natural
        // big-endian key value into a host u32 (via ByteReverseWords
        // on a little-endian host), and stores it - so the in-memory
        // u32 reads back as the original big-endian view of the key.
        let key_be = [0x2b7e1516u32, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];
        let slot0 = 4; // SA_ENCKEY is 8 words; key is 4 words at slots 4..8
        for (i, w) in key_be.iter().enumerate() {
            sa.enckey[slot0 + i] = *w;
        }
        sa.write_phys(&mut mem, sa_addr).unwrap();

        // Plaintext.
        let pt: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        mem.store(in_addr, &pt);

        // BD.
        let mut bd = BufferDescriptor::default();
        bd.set_buflen(16);
        bd.set_sa_fetch_en();
        bd.set_pkt_int_en();
        bd.set_last_bd();
        bd.set_lifm();
        bd.set_desc_en();
        bd.sa_addr = sa_addr as u32;
        bd.srcaddr = in_addr as u32;
        bd.dstaddr = out_addr as u32;
        bd.nxtptr = bd_addr as u32;
        bd.msglen = 16;
        bd.write_phys(&mut mem, bd_addr).unwrap();

        // Run engine.
        let mut ce = CryptoEngine::new();
        ce.cebdpaddr = bd_addr as u32;
        // CECON = 0xa5 (input swap + BD fetch + START + OUT_SWAP).
        ce.write(CECON_OFF, 4, 0xa5, &mut mem);
        assert_eq!(ce.ceintsrc & CEINTSRC_PKTIF, CEINTSRC_PKTIF);

        // Output: 3ad77bb4 0d7a3660 a89ecaf3 2466ef97
        let expected: [u8; 16] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        ];
        let got = mem.load(out_addr, 16);
        assert_eq!(got, expected, "AES-128 ECB ciphertext mismatch");
    }

    #[test]
    fn sha256_abc_via_chain() {
        let mut mem = InMemoryBus::new();
        let sa_addr = 0x20000u64;
        let bd_addr = 0x20200u64;
        let in_addr = 0x20400u64;
        let upd_addr = 0x20600u64;

        let mut sa = SecurityAssociation::default();
        sa.ctrl.algo = 0b0100000; // SHA-256
        sa.ctrl.loadiv = 1;
        sa.ctrl.fb = 1;
        sa.ctrl.lnc = 1;
        // SHA-256 IV (initial state H0..H7) put into SA_AUTHIV. The
        // simulator does not actually use this - the RustCrypto
        // sha2::Sha256 implementation has the FIPS-180-4 IV baked in -
        // but the firmware stages it anyway, so we write it the way
        // the wolfSSL driver does.
        let iv = [
            0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        for (i, w) in iv.iter().enumerate() {
            sa.authiv[i] = *w;
        }
        sa.write_phys(&mut mem, sa_addr).unwrap();

        let msg = b"abc";
        mem.store(in_addr, msg);

        let mut bd = BufferDescriptor::default();
        bd.set_buflen(msg.len() as u32);
        bd.set_sa_fetch_en();
        bd.set_pkt_int_en();
        bd.set_last_bd();
        bd.set_lifm();
        bd.set_desc_en();
        bd.sa_addr = sa_addr as u32;
        bd.srcaddr = in_addr as u32;
        bd.dstaddr = 0; // hashing routes output to updptr
        bd.updptr = upd_addr as u32;
        bd.nxtptr = bd_addr as u32;
        bd.msglen = msg.len() as u32;
        bd.write_phys(&mut mem, bd_addr).unwrap();

        let mut ce = CryptoEngine::new();
        ce.cebdpaddr = bd_addr as u32;
        ce.write(CECON_OFF, 4, 0xa5, &mut mem);
        assert_eq!(ce.ceintsrc & CEINTSRC_PKTIF, CEINTSRC_PKTIF);

        // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
        //                  b00361a3 96177a9c b410ff61 f20015ad
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        let got = mem.load(upd_addr, 32);
        assert_eq!(got, expected, "SHA-256(\"abc\") digest mismatch");
    }
}
