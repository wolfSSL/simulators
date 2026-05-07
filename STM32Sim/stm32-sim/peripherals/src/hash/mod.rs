/* hash/mod.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STM32Sim.
 *
 * STM32Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STM32Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

//! Shared message-digest engine for the STM32 HASH peripheral. Owns
//! the streaming hasher; per-revision register adapters (`v1` for H7,
//! `v2` for U5) marshal MMIO writes into `Engine::feed_bytes` and read
//! the digest out of `Engine::result`.

pub mod v1;

use digest::{Digest, DynDigest};

/// `DynDigest` is the dyn-compatible hashing trait but its `box_clone`
/// drops the `Send` bound. We need both `Send` (so the engine can sit
/// in shared peripheral state behind a Mutex) and an object-safe clone
/// (so `capture_snapshot` / `restore_from_snapshot` can stash a hasher
/// without committing to a concrete algorithm). This trait composes
/// the two via a blanket impl, so any RustCrypto hasher that is
/// `DynDigest + Send + Clone` automatically satisfies it.
pub trait DynDigestSendClone: DynDigest + Send {
    fn box_clone_send(&self) -> Box<dyn DynDigestSendClone>;
}

impl<T> DynDigestSendClone for T
where
    T: DynDigest + Send + Clone + 'static,
{
    fn box_clone_send(&self) -> Box<dyn DynDigestSendClone> {
        Box::new(self.clone())
    }
}

fn fresh_hasher(algo: Algo) -> Box<dyn DynDigestSendClone> {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Sha224, Sha256, Sha384, Sha512};
    match algo {
        Algo::Sha1 => Box::new(Sha1::new()),
        Algo::Md5 => Box::new(Md5::new()),
        Algo::Sha224 => Box::new(Sha224::new()),
        Algo::Sha256 => Box::new(Sha256::new()),
        Algo::Sha384 => Box::new(Sha384::new()),
        Algo::Sha512 => Box::new(Sha512::new()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Md5,
    Sha224,
    Sha256,
    /// U5/H5/H7S only.
    Sha384,
    /// U5/H5/H7S only.
    Sha512,
}

impl Algo {
    pub fn output_words(self) -> usize {
        match self {
            Algo::Sha1 => 5,     // 160 bit
            Algo::Md5 => 4,      // 128 bit
            Algo::Sha224 => 7,   // 224 bit
            Algo::Sha256 => 8,   // 256 bit
            Algo::Sha384 => 12,  // 384 bit
            Algo::Sha512 => 16,  // 512 bit
        }
    }

    /// HMAC block size in bytes - the unit at which HMAC pads the
    /// key with `K_pad ⊕ ipad` / `K_pad ⊕ opad`. SHA-384/512 use a
    /// 1024-bit (128-byte) compression block, the rest use 512-bit
    /// (64-byte).
    pub fn block_size(self) -> usize {
        match self {
            Algo::Md5 | Algo::Sha1 | Algo::Sha224 | Algo::Sha256 => 64,
            Algo::Sha384 | Algo::Sha512 => 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Word,
    Halfword,
    Byte,
    Bit,
}

impl DataType {
    pub fn from_bits(bits: u32) -> Self {
        match bits & 0x3 {
            0 => DataType::Word,
            1 => DataType::Halfword,
            2 => DataType::Byte,
            _ => DataType::Bit,
        }
    }
}

/// Where the engine is in the H7's hardware-HMAC three-DCAL flow.
/// Plain hashing stays at `Off`. wolfSSL's `wc_Stm32_Hmac_SetKey`
/// emits the first DCAL (key1), `wc_Stm32_Hmac_Final` emits the
/// second (message) and third (key again, for the outer hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacPhase {
    Off,
    Key1,
    Msg,
    Key2,
}

/// Streaming digest engine. The peripheral feeds 32-bit words from
/// DIN; we accumulate the byte stream and forward to a RustCrypto
/// `Digest` chosen at INIT time. On `finalize` we stage the result in
/// 32-bit big-endian words for the HR registers to read out.
pub struct Engine {
    algo: Algo,
    datatype: DataType,
    hasher: Option<Box<dyn DynDigestSendClone>>,
    pub finalised: bool,
    /// Up to 64 bytes of digest output, packed as 32-bit BE words.
    /// SHA-512 needs 16 words; smaller digests use the prefix.
    pub result: [u32; 16],
    pub bytes_fed: u64,
    saved_hasher: Option<Box<dyn DynDigestSendClone>>,
    saved_bytes_fed: u64,
    saved_pending_capture: bool,
    /// HMAC state. The H7 HASH peripheral has a hardware HMAC mode
    /// gated by CR.MODE bit 6: software writes the key, then DCAL
    /// (peripheral applies K_pad ⊕ ipad and starts the inner hash);
    /// then the message, then DCAL (inner hash finalised, peripheral
    /// applies K_pad ⊕ opad); then the key again, then DCAL (outer
    /// hash finalised, HMAC available in HR). We follow that
    /// three-phase pump.
    pub hmac_phase: HmacPhase,
    pub hmac_key_buf: Vec<u8>,
    /// Outer hasher kept alive across phase 1 so DCAL #2 can fold
    /// the inner digest into it without re-deriving K_pad.
    hmac_outer: Option<Box<dyn DynDigestSendClone>>,
    /// Snapshot fields that mirror the HMAC state above. wolfSSL's
    /// SaveContext (between SetKey and Final) reads CSR; our snapshot
    /// captures the engine state, including HMAC phase + outer
    /// hasher, so RestoreContext re-creates the post-SetKey state.
    saved_hmac_phase: HmacPhase,
    saved_hmac_key_buf: Vec<u8>,
    saved_hmac_outer: Option<Box<dyn DynDigestSendClone>>,
}

impl Default for Engine {
    fn default() -> Self {
        Self {
            algo: Algo::Sha256,
            datatype: DataType::Byte,
            hasher: None,
            finalised: false,
            result: [0; 16],
            bytes_fed: 0,
            saved_hasher: None,
            saved_bytes_fed: 0,
            saved_pending_capture: false,
            hmac_phase: HmacPhase::Off,
            hmac_key_buf: Vec::new(),
            hmac_outer: None,
            saved_hmac_phase: HmacPhase::Off,
            saved_hmac_key_buf: Vec::new(),
            saved_hmac_outer: None,
        }
    }
}

impl Engine {
    pub fn init(&mut self, algo: Algo, datatype: DataType) {
        self.init_with_mode(algo, datatype, false);
    }

    /// Init for either plain hashing (`hmac=false`) or hardware-HMAC
    /// mode (`hmac=true`, CR.MODE bit 6 set). HMAC mode starts in
    /// the `Key1` phase: software is about to feed the key.
    pub fn init_with_mode(&mut self, algo: Algo, datatype: DataType, hmac: bool) {
        self.algo = algo;
        self.datatype = datatype;
        self.hasher = Some(fresh_hasher(algo));
        self.finalised = false;
        self.result = [0; 16];
        self.bytes_fed = 0;
        self.saved_hasher = None;
        self.saved_bytes_fed = 0;
        self.saved_pending_capture = false;
        self.hmac_phase = if hmac { HmacPhase::Key1 } else { HmacPhase::Off };
        self.hmac_key_buf.clear();
        self.hmac_outer = None;
        self.saved_hmac_phase = HmacPhase::Off;
        self.saved_hmac_key_buf.clear();
        self.saved_hmac_outer = None;
    }

    /// Snapshot the current hasher (called when firmware does its
    /// SaveContext - reads the CSR registers). After this, any
    /// number of restores via `restore_from_snapshot` re-create the
    /// hasher at this exact point.
    pub fn capture_snapshot(&mut self) {
        if let Some(h) = self.hasher.as_ref() {
            self.saved_hasher = Some(h.box_clone_send());
            self.saved_bytes_fed = self.bytes_fed;
            self.saved_pending_capture = true;
            self.saved_hmac_phase = self.hmac_phase;
            self.saved_hmac_key_buf = self.hmac_key_buf.clone();
            self.saved_hmac_outer = self
                .hmac_outer
                .as_ref()
                .map(|h| h.box_clone_send());
        }
    }

    /// Returns true if a snapshot exists and was restored.
    pub fn restore_from_snapshot(&mut self) -> bool {
        if let Some(h) = self.saved_hasher.as_ref() {
            self.hasher = Some(h.box_clone_send());
            self.bytes_fed = self.saved_bytes_fed;
            self.finalised = false;
            self.result = [0; 16];
            self.hmac_phase = self.saved_hmac_phase;
            self.hmac_key_buf = self.saved_hmac_key_buf.clone();
            self.hmac_outer = self
                .saved_hmac_outer
                .as_ref()
                .map(|h| h.box_clone_send());
            true
        } else {
            false
        }
    }

    pub fn has_snapshot(&self) -> bool {
        self.saved_hasher.is_some()
    }

    /// Append a 32-bit DIN word. `valid_bytes` defaults to 4; on the
    /// last partial word it is whatever NBLW says (1..=4 bytes carry
    /// data; bits beyond that are ignored).
    pub fn feed_word(&mut self, value: u32, valid_bytes: u8) {
        if self.finalised {
            return;
        }
        let swapped = match self.datatype {
            DataType::Word => value,
            DataType::Halfword => value.rotate_right(16),
            DataType::Byte => value.swap_bytes(),
            DataType::Bit => {
                let mut out = 0u32;
                for i in 0..4 {
                    let b = ((value >> (i * 8)) & 0xFF) as u8;
                    out |= (b.reverse_bits() as u32) << ((3 - i) * 8);
                }
                out
            }
        };
        let bytes = swapped.to_be_bytes();
        let n = valid_bytes.min(4) as usize;
        match self.hmac_phase {
            HmacPhase::Key1 | HmacPhase::Key2 => {
                // Collect the key. For Key2 we just discard the
                // duplicate bytes - we already used the key during
                // Key1, and the outer hasher was set up at the end
                // of the message phase.
                if self.hmac_phase == HmacPhase::Key1 {
                    self.hmac_key_buf.extend_from_slice(&bytes[..n]);
                }
                self.bytes_fed += n as u64;
            }
            HmacPhase::Off | HmacPhase::Msg => {
                if let Some(h) = self.hasher.as_mut() {
                    h.update(&bytes[..n]);
                    self.bytes_fed += n as u64;
                }
            }
        }
    }

    pub fn finalize(&mut self) {
        if self.finalised {
            return;
        }
        match self.hmac_phase {
            HmacPhase::Off => self.finalize_plain(),
            HmacPhase::Key1 => self.hmac_finish_key1(),
            HmacPhase::Msg => self.hmac_finish_msg(),
            HmacPhase::Key2 => self.hmac_finish_key2(),
        }
    }

    fn finalize_plain(&mut self) {
        let mut cloned = match self.hasher.as_ref() {
            Some(h) => h.box_clone_send(),
            None => return,
        };
        self.stage_digest(cloned.finalize_reset().to_vec());
        self.finalised = true;
    }

    /// HMAC phase 1 DCAL: software has fed the key. Pad / hash the
    /// key per HMAC spec, build the inner hasher with `K_pad ⊕ ipad`
    /// already absorbed (so subsequent message DIN writes feed
    /// straight in), and prepare the outer hasher pre-loaded with
    /// `K_pad ⊕ opad`.
    fn hmac_finish_key1(&mut self) {
        let block_size = self.algo.block_size();
        // If the key is longer than the block, HMAC pre-hashes it.
        let mut key_pad = if self.hmac_key_buf.len() > block_size {
            let mut h = fresh_hasher(self.algo);
            h.update(&self.hmac_key_buf);
            h.finalize_reset().to_vec()
        } else {
            std::mem::take(&mut self.hmac_key_buf)
        };
        key_pad.resize(block_size, 0);

        let mut ipad = vec![0u8; block_size];
        let mut opad = vec![0u8; block_size];
        for i in 0..block_size {
            ipad[i] = key_pad[i] ^ 0x36;
            opad[i] = key_pad[i] ^ 0x5c;
        }
        let mut inner = fresh_hasher(self.algo);
        inner.update(&ipad);
        let mut outer = fresh_hasher(self.algo);
        outer.update(&opad);
        self.hasher = Some(inner);
        self.hmac_outer = Some(outer);
        self.hmac_phase = HmacPhase::Msg;
        // No HR write yet - HMAC isn't done. wolfSSL just polls
        // SR.DCIS and moves on.
    }

    /// HMAC phase 2 DCAL: message is in `self.hasher` (which is the
    /// inner hasher loaded with `K_pad ⊕ ipad`). Finalise it, fold
    /// the digest into the outer hasher, and switch to phase 3.
    fn hmac_finish_msg(&mut self) {
        let mut inner_clone = match self.hasher.as_ref() {
            Some(h) => h.box_clone_send(),
            None => return,
        };
        let inner_digest = inner_clone.finalize_reset();
        let mut outer = match self.hmac_outer.take() {
            Some(o) => o,
            None => return,
        };
        outer.update(&inner_digest);
        self.hasher = Some(outer);
        self.hmac_phase = HmacPhase::Key2;
    }

    /// HMAC phase 3 DCAL: software has fed the key again (we
    /// ignored the bytes in `feed_word`). Finalise the outer hasher
    /// and stage the HMAC into the result registers.
    fn hmac_finish_key2(&mut self) {
        let mut cloned = match self.hasher.as_ref() {
            Some(h) => h.box_clone_send(),
            None => return,
        };
        self.stage_digest(cloned.finalize_reset().to_vec());
        self.finalised = true;
        self.hmac_phase = HmacPhase::Off;
    }

    fn stage_digest(&mut self, digest: Vec<u8>) {
        for (i, chunk) in digest.chunks(4).enumerate() {
            if i >= self.result.len() {
                break;
            }
            let mut buf = [0u8; 4];
            for (j, b) in chunk.iter().enumerate() {
                buf[j] = *b;
            }
            self.result[i] = u32::from_be_bytes(buf);
        }
    }

    pub fn algo(&self) -> Algo {
        self.algo
    }

    pub fn datatype(&self) -> DataType {
        self.datatype
    }
}
