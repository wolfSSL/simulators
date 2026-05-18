/* ce/algo.rs
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

//! Execute a single Crypto-Engine descriptor.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use anyhow::Result;
use cipher::{KeyIvInit, StreamCipher};
use pic32mz_sim_core::MemBus;

use super::bd::{BufferDescriptor, SecurityAssociation};

const ALGO_HMAC1: u8 = 0b0100_0000;
const ALGO_SHA256: u8 = 0b0010_0000;
const ALGO_SHA1: u8 = 0b0001_0000;
const ALGO_MD5: u8 = 0b0000_1000;
const ALGO_AES: u8 = 0b0000_0100;
const ALGO_TDES: u8 = 0b0000_0010;
const ALGO_DES: u8 = 0b0000_0001;

const CRYPTOALGO_AES_GCM: u8 = 0b1110;
const CRYPTOALGO_RCTR: u8 = 0b1101;
const CRYPTOALGO_RCBC: u8 = 0b1001;
const CRYPTOALGO_RECB: u8 = 0b1000;
const CRYPTOALGO_TCBC: u8 = 0b0101;
const CRYPTOALGO_TECB: u8 = 0b0100;
const CRYPTOALGO_CBC: u8 = 0b0001;
const CRYPTOALGO_ECB: u8 = 0b0000;

const KEYSIZE_128: u8 = 0b00;
const KEYSIZE_192: u8 = 0b01;
const KEYSIZE_256: u8 = 0b10;

pub fn execute(
    sa: &SecurityAssociation,
    bd: &BufferDescriptor,
    out_swap: bool,
    mem: &mut dyn MemBus,
) -> Result<()> {
    let mut input = vec![0u8; bd.buflen() as usize];
    if !input.is_empty() {
        mem.read_phys(bd.srcaddr as u64, &mut input)?;
    }
    let msg_len = bd.msglen as usize;

    let algo = sa.ctrl.algo;
    let encrypt = sa.ctrl.enctype == 1;

    if (algo & (ALGO_SHA256 | ALGO_SHA1 | ALGO_MD5 | ALGO_HMAC1)) != 0 {
        let trimmed = &input[..msg_len.min(input.len())];
        let digest = hash(algo, trimmed)?;
        let mut out = digest;
        // PIC32MZ Crypto Engine writes its "internal" big-endian-per-word
        // result to RAM unless CECON.OUT_SWAP is set, in which case the
        // engine byte-swaps each word on the way out. wolfSSL on EC
        // silicon (no out-swap) compensates with a software
        // ByteReverseWords after reading the buffer; on EF it just
        // memcpys. RustCrypto returns the final-form bytes, so to
        // mimic the silicon we byte-swap when out-swap is OFF.
        if !out_swap {
            byte_swap_words(&mut out);
        }
        mem.write_phys(bd.updptr as u64, &out)?;
        return Ok(());
    }

    if (algo & ALGO_AES) != 0 {
        let key_len = match sa.ctrl.keysize {
            KEYSIZE_128 => 16,
            KEYSIZE_192 => 24,
            KEYSIZE_256 => 32,
            other => anyhow::bail!("unknown KEYSIZE {other}"),
        };
        let key = sa.cipher_key(key_len);
        let iv = if sa.ctrl.loadiv != 0 {
            sa.cipher_iv(16)
        } else {
            vec![0u8; 16]
        };
        let mut buf = input.clone();
        aes_run(sa.ctrl.cryptoalgo, &key, &iv, &mut buf, msg_len, encrypt)?;
        if !out_swap {
            byte_swap_words(&mut buf);
        }
        mem.write_phys(bd.dstaddr as u64, &buf)?;
        return Ok(());
    }

    if (algo & ALGO_TDES) != 0 {
        let key = sa.cipher_key(24);
        let iv = if sa.ctrl.loadiv != 0 {
            sa.cipher_iv(8)
        } else {
            vec![0u8; 8]
        };
        let mut buf = input.clone();
        tdes_run(sa.ctrl.cryptoalgo, &key, &iv, &mut buf, msg_len, encrypt)?;
        if !out_swap {
            byte_swap_words(&mut buf);
        }
        mem.write_phys(bd.dstaddr as u64, &buf)?;
        return Ok(());
    }

    if (algo & ALGO_DES) != 0 {
        let key = sa.cipher_key(8);
        let iv = if sa.ctrl.loadiv != 0 {
            sa.cipher_iv(8)
        } else {
            vec![0u8; 8]
        };
        let mut buf = input.clone();
        des_run(sa.ctrl.cryptoalgo, &key, &iv, &mut buf, msg_len, encrypt)?;
        if !out_swap {
            byte_swap_words(&mut buf);
        }
        mem.write_phys(bd.dstaddr as u64, &buf)?;
        return Ok(());
    }

    anyhow::bail!("unsupported SA.ALGO = 0x{algo:02x}")
}

fn byte_swap_words(buf: &mut [u8]) {
    let chunks = buf.len() / 4;
    for i in 0..chunks {
        let off = i * 4;
        buf.swap(off, off + 3);
        buf.swap(off + 1, off + 2);
    }
}

fn hash(algo: u8, input: &[u8]) -> Result<Vec<u8>> {
    use digest::Digest;
    if (algo & ALGO_SHA256) != 0 {
        let mut h = sha2::Sha256::new();
        h.update(input);
        Ok(h.finalize().to_vec())
    } else if (algo & ALGO_SHA1) != 0 {
        let mut h = sha1::Sha1::new();
        h.update(input);
        Ok(h.finalize().to_vec())
    } else if (algo & ALGO_MD5) != 0 {
        let mut h = md5::Md5::new();
        h.update(input);
        Ok(h.finalize().to_vec())
    } else {
        anyhow::bail!("hash: unsupported ALGO bits 0x{algo:02x}")
    }
}

fn aes_ecb_block(key: &[u8], block: &mut [u8; 16], encrypt: bool) {
    let mut ga: GenericArray<u8, aes::cipher::consts::U16> =
        GenericArray::clone_from_slice(block);
    match key.len() {
        16 => {
            let c = Aes128::new_from_slice(key).expect("AES-128 key");
            if encrypt { c.encrypt_block(&mut ga); } else { c.decrypt_block(&mut ga); }
        }
        24 => {
            let c = Aes192::new_from_slice(key).expect("AES-192 key");
            if encrypt { c.encrypt_block(&mut ga); } else { c.decrypt_block(&mut ga); }
        }
        32 => {
            let c = Aes256::new_from_slice(key).expect("AES-256 key");
            if encrypt { c.encrypt_block(&mut ga); } else { c.decrypt_block(&mut ga); }
        }
        _ => unreachable!(),
    }
    block.copy_from_slice(&ga);
}

fn aes_run(
    cryptoalgo: u8,
    key: &[u8],
    iv: &[u8],
    buf: &mut [u8],
    msg_len: usize,
    encrypt: bool,
) -> Result<()> {
    match cryptoalgo {
        CRYPTOALGO_RECB => {
            let block_count = msg_len / 16;
            for i in 0..block_count {
                let off = i * 16;
                let mut block = [0u8; 16];
                block.copy_from_slice(&buf[off..off + 16]);
                aes_ecb_block(key, &mut block, encrypt);
                buf[off..off + 16].copy_from_slice(&block);
            }
            Ok(())
        }
        CRYPTOALGO_RCBC => aes_cbc(key, iv, buf, msg_len, encrypt),
        CRYPTOALGO_RCTR => aes_ctr_run(key, iv, buf, msg_len),
        CRYPTOALGO_AES_GCM => aes_gcm_stream(key, iv, buf, msg_len),
        other => anyhow::bail!("AES cryptoalgo 0x{other:x} not supported"),
    }
}

fn aes_cbc(key: &[u8], iv: &[u8], buf: &mut [u8], msg_len: usize, encrypt: bool) -> Result<()> {
    let block_count = msg_len / 16;
    let mut prev = [0u8; 16];
    prev.copy_from_slice(&iv[..16]);
    if encrypt {
        for i in 0..block_count {
            let off = i * 16;
            let mut block = [0u8; 16];
            for j in 0..16 {
                block[j] = buf[off + j] ^ prev[j];
            }
            aes_ecb_block(key, &mut block, true);
            buf[off..off + 16].copy_from_slice(&block);
            prev = block;
        }
    } else {
        for i in 0..block_count {
            let off = i * 16;
            let mut ct = [0u8; 16];
            ct.copy_from_slice(&buf[off..off + 16]);
            let mut pt = ct;
            aes_ecb_block(key, &mut pt, false);
            for j in 0..16 {
                pt[j] ^= prev[j];
            }
            buf[off..off + 16].copy_from_slice(&pt);
            prev = ct;
        }
    }
    Ok(())
}

fn aes_ctr_run(key: &[u8], iv: &[u8], buf: &mut [u8], msg_len: usize) -> Result<()> {
    type C128 = ctr::Ctr128BE<Aes128>;
    type C192 = ctr::Ctr128BE<Aes192>;
    type C256 = ctr::Ctr128BE<Aes256>;
    let iv_ga: &GenericArray<u8, aes::cipher::consts::U16> = GenericArray::from_slice(&iv[..16]);
    match key.len() {
        16 => {
            let key_ga: &GenericArray<u8, aes::cipher::consts::U16> =
                GenericArray::from_slice(key);
            let mut c = C128::new(key_ga, iv_ga);
            c.apply_keystream(&mut buf[..msg_len]);
        }
        24 => {
            let key_ga: &GenericArray<u8, aes::cipher::consts::U24> =
                GenericArray::from_slice(key);
            let mut c = C192::new(key_ga, iv_ga);
            c.apply_keystream(&mut buf[..msg_len]);
        }
        32 => {
            let key_ga: &GenericArray<u8, aes::cipher::consts::U32> =
                GenericArray::from_slice(key);
            let mut c = C256::new(key_ga, iv_ga);
            c.apply_keystream(&mut buf[..msg_len]);
        }
        n => anyhow::bail!("AES-CTR key length {n} unsupported"),
    }
    Ok(())
}

fn aes_gcm_stream(key: &[u8], iv: &[u8], buf: &mut [u8], msg_len: usize) -> Result<()> {
    // PIC32MZ AES-GCM hardware streams the data through CTR with
    // J0 derived from the IV. wolfSSL does the GHASH+tag in software
    // (see aes.c PIC32 GCM call sites); the simulator only needs to
    // emulate the data pass.
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(&iv[..12]);
    counter[15] = 2;
    aes_ctr_run(key, &counter, buf, msg_len)
}

fn des_run(
    cryptoalgo: u8,
    key: &[u8],
    iv: &[u8],
    buf: &mut [u8],
    msg_len: usize,
    encrypt: bool,
) -> Result<()> {
    use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use des::Des;
    let cipher = Des::new_from_slice(key).map_err(|e| anyhow::anyhow!("DES key init: {e}"))?;
    let block_count = msg_len / 8;
    match cryptoalgo {
        CRYPTOALGO_ECB => {
            for i in 0..block_count {
                let off = i * 8;
                let mut block = GenericArray::clone_from_slice(&buf[off..off + 8]);
                if encrypt {
                    cipher.encrypt_block(&mut block);
                } else {
                    cipher.decrypt_block(&mut block);
                }
                buf[off..off + 8].copy_from_slice(&block);
            }
        }
        CRYPTOALGO_CBC => {
            let mut prev = [0u8; 8];
            prev.copy_from_slice(&iv[..8]);
            if encrypt {
                for i in 0..block_count {
                    let off = i * 8;
                    let mut block = [0u8; 8];
                    for j in 0..8 {
                        block[j] = buf[off + j] ^ prev[j];
                    }
                    let mut ga = GenericArray::clone_from_slice(&block);
                    cipher.encrypt_block(&mut ga);
                    block.copy_from_slice(&ga);
                    buf[off..off + 8].copy_from_slice(&block);
                    prev = block;
                }
            } else {
                for i in 0..block_count {
                    let off = i * 8;
                    let mut ct = [0u8; 8];
                    ct.copy_from_slice(&buf[off..off + 8]);
                    let mut ga = GenericArray::clone_from_slice(&ct);
                    cipher.decrypt_block(&mut ga);
                    let mut pt = [0u8; 8];
                    for j in 0..8 {
                        pt[j] = ga[j] ^ prev[j];
                    }
                    buf[off..off + 8].copy_from_slice(&pt);
                    prev = ct;
                }
            }
        }
        other => anyhow::bail!("DES cryptoalgo 0x{other:x} not supported"),
    }
    Ok(())
}

fn tdes_run(
    cryptoalgo: u8,
    key: &[u8],
    iv: &[u8],
    buf: &mut [u8],
    msg_len: usize,
    encrypt: bool,
) -> Result<()> {
    use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use des::TdesEde3;
    let cipher = TdesEde3::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("3DES key init: {e}"))?;
    let block_count = msg_len / 8;
    match cryptoalgo {
        CRYPTOALGO_TECB => {
            for i in 0..block_count {
                let off = i * 8;
                let mut block = GenericArray::clone_from_slice(&buf[off..off + 8]);
                if encrypt {
                    cipher.encrypt_block(&mut block);
                } else {
                    cipher.decrypt_block(&mut block);
                }
                buf[off..off + 8].copy_from_slice(&block);
            }
        }
        CRYPTOALGO_TCBC => {
            let mut prev = [0u8; 8];
            prev.copy_from_slice(&iv[..8]);
            if encrypt {
                for i in 0..block_count {
                    let off = i * 8;
                    let mut block = [0u8; 8];
                    for j in 0..8 {
                        block[j] = buf[off + j] ^ prev[j];
                    }
                    let mut ga = GenericArray::clone_from_slice(&block);
                    cipher.encrypt_block(&mut ga);
                    block.copy_from_slice(&ga);
                    buf[off..off + 8].copy_from_slice(&block);
                    prev = block;
                }
            } else {
                for i in 0..block_count {
                    let off = i * 8;
                    let mut ct = [0u8; 8];
                    ct.copy_from_slice(&buf[off..off + 8]);
                    let mut ga = GenericArray::clone_from_slice(&ct);
                    cipher.decrypt_block(&mut ga);
                    let mut pt = [0u8; 8];
                    for j in 0..8 {
                        pt[j] = ga[j] ^ prev[j];
                    }
                    buf[off..off + 8].copy_from_slice(&pt);
                    prev = ct;
                }
            }
        }
        other => anyhow::bail!("3DES cryptoalgo 0x{other:x} not supported"),
    }
    Ok(())
}

#[cfg(test)]
mod selftests {
    use super::*;

    #[test]
    fn byte_swap_words_simple() {
        let mut buf = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        byte_swap_words(&mut buf);
        assert_eq!(buf, [0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]);
    }
}
