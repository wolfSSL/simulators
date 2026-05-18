/* ce/polling.rs
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
 */

//! Polling-mode (streaming large hash) support for the PIC32MZ Crypto
//! Engine. The wolfSSL `WOLFSSL_PIC32MZ_LARGE_HASH` path arms the
//! engine for incremental hashing: `CECON=0xa7`/`0x27` switches the
//! engine into polling mode, then the firmware sets `BD_CTRL.DESC_EN`
//! on successive BDs in a round-robin ring as each fills up. The
//! hardware processes each BD as it becomes enabled, carrying the
//! running digest forward across BDs, and the final BD (with LAST_BD
//! and LIFM set) commits the digest to UPDPTR.
//!
//! We can't directly observe `BD_CTRL.DESC_EN` stores — Unicorn 2.1's
//! `MEM_WRITE` hook does not fire on writes to `mem_map`'d RAM. So we
//! register a "polling tick" that fires from the global block hook on
//! every translation-block boundary, and on each tick we re-scan the
//! BD chain for any BD with `DESC_EN=1`, hash its data through a
//! running RustCrypto digest, clear `DESC_EN`, and on `LAST_BD/LIFM`
//! commit the final digest to UPDPTR. The wolfSSL driver's
//! `while (BD.DESC_EN && ++checks < N)` poll loop is one short TB; the
//! tick fires every iteration so the firmware never sees DESC_EN
//! linger past one poll-loop turn.

use anyhow::Result;
use digest::Digest;
use pic32mz_sim_core::MemBus;
use std::sync::{Arc, Mutex};

use super::bd::{BufferDescriptor, SecurityAssociation};

const ALGO_HMAC1: u8 = 0b0100_0000;
const ALGO_SHA256: u8 = 0b0010_0000;
const ALGO_SHA1: u8 = 0b0001_0000;
const ALGO_MD5: u8 = 0b0000_1000;

const DESC_EN_BIT: u32 = 1 << 31;

/// Incremental digest accumulator carried across BDs.
enum HashCtx {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl HashCtx {
    fn from_algo(algo: u8) -> Result<Self> {
        if algo & ALGO_HMAC1 != 0 {
            anyhow::bail!("polling-mode HMAC not supported (ALGO=0x{algo:02x})");
        }
        if algo & ALGO_SHA256 != 0 {
            Ok(HashCtx::Sha256(sha2::Sha256::new()))
        } else if algo & ALGO_SHA1 != 0 {
            Ok(HashCtx::Sha1(sha1::Sha1::new()))
        } else if algo & ALGO_MD5 != 0 {
            Ok(HashCtx::Md5(md5::Md5::new()))
        } else {
            anyhow::bail!("polling-mode hash: unsupported ALGO=0x{algo:02x}")
        }
    }
    fn update(&mut self, data: &[u8]) {
        match self {
            HashCtx::Md5(h) => h.update(data),
            HashCtx::Sha1(h) => h.update(data),
            HashCtx::Sha256(h) => h.update(data),
        }
    }
    fn finalize(self) -> Vec<u8> {
        match self {
            HashCtx::Md5(h) => h.finalize().to_vec(),
            HashCtx::Sha1(h) => h.finalize().to_vec(),
            HashCtx::Sha256(h) => h.finalize().to_vec(),
        }
    }
}

struct State {
    algo: u8,
    ctx: Option<HashCtx>,
    bytes_fed: u64,
    out_swap: bool,
    completed: bool,
    /// Physical addresses of BDs in the chain (each at offset 0 within
    /// the BD's 32-byte layout).
    bd_addrs: Vec<u64>,
    /// Index of the tick registration; used to unregister on completion
    /// so subsequent (e.g. AES) MMIO traffic doesn't drive a stale
    /// polling-mode tick.
    tick_idx: Option<usize>,
}

/// Walk the BD chain starting at `bd0` collecting up to 8 BD physical
/// addresses. The chain is terminated by a self-pointer or a NULL
/// NXTPTR (wolfSSL's reset_engine wraps NXTPTR back to bd[0]).
fn collect_chain(bd0: u64, mem: &mut dyn MemBus) -> Result<Vec<u64>> {
    let mut addrs = Vec::new();
    let mut cur = bd0;
    for _ in 0..8 {
        if cur == 0 {
            break;
        }
        if addrs.contains(&cur) {
            break;
        }
        addrs.push(cur);
        let bd = BufferDescriptor::read_phys(mem, cur)?;
        let next = bd.nxtptr as u64;
        if next == cur {
            break;
        }
        cur = next;
    }
    if addrs.is_empty() {
        anyhow::bail!("polling-mode: empty BD chain");
    }
    Ok(addrs)
}

/// Process a single enabled BD: feed its data into the running digest,
/// clear DESC_EN, and on LAST_BD/LIFM commit the digest to UPDPTR.
fn process_bd(state: &mut State, bd_addr: u64, mem: &mut dyn MemBus) -> Result<()> {
    let bd = BufferDescriptor::read_phys(mem, bd_addr)?;
    if !bd.desc_enabled() {
        return Ok(());
    }

    // First BD has SA_FETCH_EN; the SA tells us the algorithm.
    if state.ctx.is_none() {
        if !bd.sa_fetch_enabled() {
            anyhow::bail!(
                "polling-mode: first processed BD at 0x{bd_addr:08x} has no SA_FETCH_EN"
            );
        }
        let sa = SecurityAssociation::read_phys(mem, bd.sa_addr as u64)?;
        state.algo = sa.ctrl.algo;
        state.ctx = Some(HashCtx::from_algo(state.algo)?);
    }

    // Feed bytes. wolfSSL pads BUFLEN up to a 4-byte multiple on the
    // last BD; cap at MSGLEN-bytes_fed so the digest finalisation
    // sees exactly the true message length.
    let buflen = bd.buflen() as u64;
    let mut take = buflen as usize;
    if bd.msglen != 0 {
        let remaining = (bd.msglen as u64).saturating_sub(state.bytes_fed);
        if (take as u64) > remaining {
            take = remaining as usize;
        }
    }
    if take > 0 {
        let mut buf = vec![0u8; take];
        mem.read_phys(bd.srcaddr as u64, &mut buf)?;
        if let Some(ref mut ctx) = state.ctx {
            ctx.update(&buf);
        }
        state.bytes_fed += take as u64;
    }

    let finalize = bd.last_bd() && bd.lifm();

    // Clear DESC_EN before writing back so the firmware's poll loop
    // sees the engine "done with this BD".
    let mut updated = bd;
    updated.bd_ctrl.0 &= !DESC_EN_BIT;
    updated.write_phys(mem, bd_addr)?;

    if finalize {
        let ctx = state.ctx.take().expect("digest ctx present at finalize");
        let mut digest = ctx.finalize();
        // OUT_SWAP off (EC silicon) means firmware ByteReverseWords's
        // after reading UPDPTR; emit swapped bytes to match.
        if !state.out_swap {
            byte_swap_words(&mut digest);
        }
        mem.write_phys(bd.updptr as u64, &digest)?;
        state.completed = true;
    }
    Ok(())
}

fn byte_swap_words(buf: &mut [u8]) {
    let chunks = buf.len() / 4;
    for i in 0..chunks {
        let off = i * 4;
        buf.swap(off, off + 3);
        buf.swap(off + 1, off + 2);
    }
}

/// Arm polling-mode hash. Walks the BD chain from `cebdpaddr` and
/// registers a polling-tick callback that re-scans the chain on every
/// TB boundary. Returns the tick index (for later unregistration) and
/// a flag that flips to `true` once the chain's LAST_BD has fired
/// and the digest has been committed.
pub fn arm(
    cebdpaddr: u32,
    out_swap: bool,
    mem: &mut dyn MemBus,
) -> Result<(usize, Arc<Mutex<bool>>)> {
    if cebdpaddr == 0 {
        anyhow::bail!("polling-mode: CEBDPADDR is zero");
    }
    let bd0 = cebdpaddr as u64;
    let addrs = collect_chain(bd0, mem)?;
    log::debug!(
        "CE polling-mode arm: BD chain @ 0x{bd0:08x} ({} BDs)",
        addrs.len()
    );
    let trace = std::env::var("PIC32MZ_SIM_TRACE_POLLING").is_ok();
    if trace {
        eprintln!(
            "[poll-arm] BD chain @ 0x{bd0:08x} addrs={:?} out_swap={}",
            addrs, out_swap
        );
    }

    let state = Arc::new(Mutex::new(State {
        algo: 0,
        ctx: None,
        bytes_fed: 0,
        out_swap,
        completed: false,
        bd_addrs: addrs,
        tick_idx: None,
    }));
    let completed_flag = Arc::new(Mutex::new(false));

    let state_for_cb = state.clone();
    let completed_for_cb = completed_flag.clone();
    let callback: pic32mz_sim_core::PollingTickFn = Box::new(move |mem: &mut dyn MemBus| {
        let mut state = match state_for_cb.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if state.completed {
            return;
        }
        // Snapshot the BD addresses so we can mutate state.ctx while
        // iterating without holding the borrow on bd_addrs.
        let addrs: Vec<u64> = state.bd_addrs.clone();
        let mut progressed_any = false;
        for &bd_addr in &addrs {
            // Cheap pre-check: peek BD_CTRL via a 4-byte read and skip
            // if DESC_EN is not set. Avoids the full BD parse on every
            // tick when nothing's pending.
            let mut ctrl_bytes = [0u8; 4];
            if mem.read_phys(bd_addr, &mut ctrl_bytes).is_err() {
                continue;
            }
            let ctrl = u32::from_le_bytes(ctrl_bytes);
            if ctrl & DESC_EN_BIT == 0 {
                continue;
            }
            if trace {
                eprintln!(
                    "[poll-tick]   processing BD @ 0x{:08x} ctrl=0x{:08x}",
                    bd_addr, ctrl
                );
            }
            if let Err(e) = process_bd(&mut state, bd_addr, mem) {
                log::error!("CE polling-mode BD process failed: {e:?}");
                break;
            }
            progressed_any = true;
            if state.completed {
                break;
            }
        }
        if state.completed && progressed_any {
            if let Ok(mut flag) = completed_for_cb.lock() {
                *flag = true;
            }
        }
    });

    let tick_idx = pic32mz_sim_core::register_polling_tick(callback);
    if let Ok(mut s) = state.lock() {
        s.tick_idx = Some(tick_idx);
    }

    let _ = mem;
    Ok((tick_idx, completed_flag))
}

/// Disarm a previously-armed polling-tick by index.
pub fn disarm(tick_idx: usize) {
    pic32mz_sim_core::unregister_polling_tick(tick_idx);
}
