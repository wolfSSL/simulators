/* tcp.rs
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

//! End-to-end tests against the TCP server. A minimal host speaks
//! libtropic's `hal/posix/tcp/` framing, the L1 polling convention, the
//! Noise_KK1 handshake and chunked Encrypted_Cmd transfers.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand_core::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Static};

use tropic01_sim::frame::{build_request, status, GET_RESPONSE_REQ_ID};
use tropic01_sim::object_store::{LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE};
use tropic01_sim::session::{lt_hkdf, sha256, sha256_concat, PROTOCOL_NAME};
use tropic01_sim::tcp_proto::{TcpFrame, TcpTag};

struct ServerGuard {
    child: Child,
    port: u16,
    store: PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_server(personality: &str) -> ServerGuard {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_tcp_server"))
        .env("TROPIC01_SIM_BIND", "127.0.0.1")
        .env("TROPIC01_SIM_PORT", port.to_string())
        .env("TROPIC01_SIM_FRESH", "1")
        .env("TROPIC01_SIM_PERSONALITY", personality)
        .env("TROPIC01_SIM_STORE", dir.path().join("store.json"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tcp_server");
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return ServerGuard {
                child,
                port,
                store: dir.path().join("store.json"),
                _dir: dir,
            };
        }
        sleep(Duration::from_millis(25));
    }
    panic!("tcp_server did not start listening on port {port}");
}

struct Host {
    s: TcpStream,
    keys: Option<([u8; 32], [u8; 32], u32, u32)>,
}

impl Host {
    fn connect(port: u16) -> Self {
        Self {
            s: TcpStream::connect(("127.0.0.1", port)).unwrap(),
            keys: None,
        }
    }

    fn tcp(&mut self, tag: TcpTag, payload: Vec<u8>) -> Vec<u8> {
        TcpFrame::new(tag, payload).write_to(&mut self.s).unwrap();
        let r = TcpFrame::read_from(&mut self.s)
            .unwrap()
            .expect("eof from server");
        assert_eq!(r.tag, tag as u8);
        r.payload
    }

    /// One write transaction; returns the MISO bytes.
    fn write(&mut self, frame: &[u8]) -> Vec<u8> {
        self.tcp(TcpTag::SpiDriveCsnLow, vec![]);
        let miso = self.tcp(TcpTag::SpiSend, frame.to_vec());
        self.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
        miso
    }

    /// lt_l1_read: poll until READY, return `[STATUS][LEN][DATA][CRC]`.
    fn read(&mut self) -> Vec<u8> {
        for _ in 0..50 {
            self.tcp(TcpTag::SpiDriveCsnLow, vec![]);
            let cs = self.tcp(TcpTag::SpiSend, vec![GET_RESPONSE_REQ_ID])[0];
            if cs & 0x01 == 0 {
                self.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
                continue;
            }
            let hdr = self.tcp(TcpTag::SpiSend, vec![0, 0]);
            if hdr[0] == status::NO_RESP {
                self.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
                continue;
            }
            let mut f = hdr.clone();
            f.extend(self.tcp(TcpTag::SpiSend, vec![0; hdr[1] as usize + 2]));
            self.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
            return f;
        }
        panic!("no response");
    }

    fn l2(&mut self, req_id: u8, data: &[u8]) -> Vec<u8> {
        self.write(&build_request(req_id, data));
        self.read()
    }

    fn stpub(&mut self) -> [u8; 32] {
        let mut blob = Vec::new();
        for block in 0..30u8 {
            let f = self.l2(0x01, &[0x00, block]);
            assert_eq!(f[0], status::REQUEST_OK);
            blob.extend_from_slice(&f[2..2 + f[1] as usize]);
        }
        let len0 = u16::from_be_bytes([blob[2], blob[3]]) as usize;
        let cert = &blob[10..10 + len0];
        let marker = [0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
        let at = cert
            .windows(6)
            .position(|w| w == marker)
            .expect("X25519 SPKI")
            + 6;
        cert[at..at + 32].try_into().unwrap()
    }

    fn handshake(&mut self, pkey: u8, shipriv: [u8; 32], shipub: [u8; 32]) -> u8 {
        let stpub = self.stpub();
        let mut eh = [0u8; 32];
        OsRng.fill_bytes(&mut eh);
        let ehpriv = X25519Static::from(eh);
        let ehpub = X25519Public::from(&ehpriv).to_bytes();
        let mut req = ehpub.to_vec();
        req.push(pkey);
        let f = self.l2(0x02, &req);
        if f[0] != status::REQUEST_OK {
            return f[0];
        }
        let etpub: [u8; 32] = f[2..34].try_into().unwrap();
        let tag = &f[34..50];
        let h = sha256_concat(
            &sha256_concat(
                &sha256_concat(
                    &sha256_concat(&sha256_concat(&sha256(&PROTOCOL_NAME), &shipub), &stpub),
                    &ehpub,
                ),
                &[pkey],
            ),
            &etpub,
        );
        let et = X25519Public::from(etpub);
        let ss1 = ehpriv.diffie_hellman(&et).to_bytes();
        let ss2 = X25519Static::from(shipriv).diffie_hellman(&et).to_bytes();
        let ss3 = ehpriv.diffie_hellman(&X25519Public::from(stpub)).to_bytes();
        let mut ck = [0u8; 33];
        let (a, _) = lt_hkdf(&PROTOCOL_NAME, &ss1);
        ck[..32].copy_from_slice(&a);
        let (b, _) = lt_hkdf(&ck, &ss2);
        ck[..32].copy_from_slice(&b);
        let (c, kauth) = lt_hkdf(&ck, &ss3);
        ck[..32].copy_from_slice(&c);
        let (kcmd, kres) = lt_hkdf(&ck, b"");
        let cipher = Aes256Gcm::new_from_slice(&kauth).unwrap();
        cipher
            .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: tag, aad: &h })
            .expect("handshake tag");
        self.keys = Some((kcmd, kres, 0, 0));
        f[0]
    }

    fn nonce(n: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[..4].copy_from_slice(&n.to_le_bytes());
        iv
    }

    /// Send an L3 command in 252-byte chunks, collect the result chunks and
    /// return the plaintext result, or the L2 status that ended it.
    fn l3(&mut self, cmd: &[u8]) -> Result<Vec<u8>, u8> {
        self.l3_resend(cmd, None)
    }

    /// Like `l3`, but after response frame `resend_at` (0 = the
    /// acknowledgement, 1 = the first result chunk, ...) ask for it again
    /// with Resend_Req, as libtropic does after a CRC error, check the
    /// replay is identical and carry on.
    fn l3_resend(&mut self, cmd: &[u8], resend_at: Option<usize>) -> Result<Vec<u8>, u8> {
        let (kcmd, kres, nc, nr) = self.keys.unwrap();
        let ct = Aes256Gcm::new_from_slice(&kcmd)
            .unwrap()
            .encrypt(Nonce::from_slice(&Self::nonce(nc)), cmd)
            .unwrap();
        let mut packet = (cmd.len() as u16).to_le_bytes().to_vec();
        packet.extend(ct);
        let chunks: Vec<&[u8]> = packet.chunks(252).collect();
        for (i, c) in chunks.iter().enumerate() {
            let f = self.l2(0x04, c);
            let want = if i + 1 == chunks.len() {
                status::REQUEST_OK
            } else {
                status::REQUEST_CONT
            };
            if f[0] != want {
                return Err(f[0]);
            }
            if i + 1 == chunks.len() && resend_at == Some(0) {
                assert_eq!(self.l2(0x10, &[]), f, "replayed acknowledgement");
            }
        }
        let mut res = Vec::new();
        let mut index = 0;
        loop {
            let f = self.read();
            index += 1;
            if resend_at == Some(index) {
                assert_eq!(self.l2(0x10, &[]), f, "replayed result chunk");
            }
            match f[0] {
                status::RESULT_CONT => res.extend_from_slice(&f[2..2 + f[1] as usize]),
                status::RESULT_OK => {
                    res.extend_from_slice(&f[2..2 + f[1] as usize]);
                    break;
                }
                other => return Err(other),
            }
        }
        let size = u16::from_le_bytes([res[0], res[1]]) as usize;
        assert_eq!(res.len(), 2 + size + 16);
        let pt = Aes256Gcm::new_from_slice(&kres)
            .unwrap()
            .decrypt(Nonce::from_slice(&Self::nonce(nr)), &res[2..])
            .expect("result tag");
        self.keys = Some((kcmd, kres, nc + 1, nr + 1));
        Ok(pt)
    }
}

#[test]
fn write_transaction_miso_matches_chip() {
    let server = spawn_server("es-0.1.2");
    let mut h = Host::connect(server.port);
    let miso = h.write(&build_request(0x01, &[0x02, 0x00]));
    assert_eq!(miso, vec![0x01, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // First poll after a request: busy.
    h.tcp(TcpTag::SpiDriveCsnLow, vec![]);
    assert_eq!(
        h.tcp(TcpTag::SpiSend, vec![GET_RESPONSE_REQ_ID]),
        vec![0x00]
    );
    h.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
    let f = h.read();
    assert_eq!(f[..2], [status::REQUEST_OK, 4]);
}

#[test]
fn chunked_l3_round_trips() {
    let server = spawn_server("es-0.1.2");
    let mut h = Host::connect(server.port);
    assert_eq!(
        h.handshake(0, LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE),
        status::REQUEST_OK
    );
    for len in [1usize, 235, 236, 1000, 4096] {
        let mut cmd = vec![0x01];
        cmd.extend((0..len).map(|i| i as u8));
        let r = h.l3(&cmd).expect("ping");
        assert_eq!(r[0], 0xc3);
        assert_eq!(&r[1..], &cmd[1..]);
    }
    // 255 random bytes need two result chunks.
    let r = h.l3(&[0x50, 255]).expect("random");
    assert_eq!(r.len(), 259);
}

#[test]
fn handshake_with_empty_slot_fails() {
    let server = spawn_server("es-0.1.2");
    let mut h = Host::connect(server.port);
    assert_eq!(
        h.handshake(1, LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE),
        status::HSK_ERR
    );
}

#[test]
fn production_personality_strict_sizes_close_session() {
    let server = spawn_server("2.2.0");
    let mut h = Host::connect(server.port);
    let prod_priv = tropic01_sim::object_store::LT_SH0PRIV_PROD0;
    let prod_pub = tropic01_sim::object_store::LT_SH0PUB_PROD0;
    assert_eq!(h.handshake(0, prod_priv, prod_pub), status::REQUEST_OK);
    assert_eq!(h.l3(&[0x50, 4, 0]), Err(status::GEN_ERR));
    assert_eq!(h.l3(&[0x01, 1]), Err(status::NO_SESSION));
}

#[test]
fn power_on_clears_alarm() {
    let server = spawn_server("es-0.1.2");
    let mut h = Host::connect(server.port);
    let mut hs = vec![0x42u8; 33];
    hs[32] = 4;
    h.write(&build_request(0x02, &hs));
    h.tcp(TcpTag::SpiDriveCsnLow, vec![]);
    assert_eq!(
        h.tcp(TcpTag::SpiSend, vec![GET_RESPONSE_REQ_ID])[0] & 0x02,
        0x02
    );
    h.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
    h.tcp(TcpTag::PowerOff, vec![]);
    h.tcp(TcpTag::PowerOn, vec![]);
    let f = h.l2(0x01, &[0x02, 0x00]);
    assert_eq!(f[0], status::REQUEST_OK);
}

#[test]
fn resend_keeps_the_rest_of_a_result() {
    let server = spawn_server("es-0.1.2");
    let mut h = Host::connect(server.port);
    assert_eq!(
        h.handshake(0, LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE),
        status::REQUEST_OK
    );
    // A 600-byte ping answers with RESULT_CONT, RESULT_CONT, RESULT_OK
    let mut cmd = vec![0x01];
    cmd.extend((0..600).map(|i| i as u8));
    for at in 0..=3 {
        let r = h.l3_resend(&cmd, Some(at)).expect("ping");
        assert_eq!(r[0], 0xc3);
        assert_eq!(&r[1..], &cmd[1..], "resend after frame {at}");
    }
}

#[test]
fn chip_state_survives_reconnect() {
    let server = spawn_server("es-0.1.2");

    // The secure session belongs to the chip, not to the connection
    let mut h1 = Host::connect(server.port);
    assert_eq!(
        h1.handshake(0, LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE),
        status::REQUEST_OK
    );
    let mut h2 = Host::connect(server.port);
    h2.keys = h1.keys;
    drop(h1);
    assert_eq!(h2.l3(&[0x01, 5]), Ok(vec![0xc3, 5]));

    // So is Maintenance mode
    let f = h2.l2(0xb3, &[0x03]);
    assert_eq!(f[0], status::REQUEST_OK);
    drop(h2);
    let mut h3 = Host::connect(server.port);
    h3.tcp(TcpTag::SpiDriveCsnLow, vec![]);
    assert_eq!(
        h3.tcp(TcpTag::SpiSend, vec![GET_RESPONSE_REQ_ID]),
        vec![0x05]
    );
    h3.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
    assert_eq!(h3.l2(0xb3, &[0x01])[0], status::REQUEST_OK);

    // And Alarm mode, which only a power cycle clears
    let mut hs = vec![0x42u8; 33];
    hs[32] = 4;
    h3.write(&build_request(0x02, &hs));
    drop(h3);
    let mut h4 = Host::connect(server.port);
    h4.tcp(TcpTag::SpiDriveCsnLow, vec![]);
    assert_eq!(
        h4.tcp(TcpTag::SpiSend, vec![GET_RESPONSE_REQ_ID])[0] & 0x02,
        0x02
    );
    h4.tcp(TcpTag::SpiDriveCsnHigh, vec![]);
    h4.tcp(TcpTag::PowerOff, vec![]);
    h4.tcp(TcpTag::PowerOn, vec![]);
    assert_eq!(h4.l2(0x01, &[0x02, 0x00])[0], status::REQUEST_OK);
}

#[test]
fn config_changes_take_effect_after_reboot() {
    let server = spawn_server("es-0.1.2");
    let mut h = Host::connect(server.port);
    assert_eq!(
        h.handshake(0, LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE),
        status::REQUEST_OK
    );
    // Allow only pairing slot 1 to ping (CFG_UAP_PING at 0x100)
    assert_eq!(
        h.l3(&[0x20, 0x00, 0x01, 0, 0x02, 0xff, 0xff, 0xff]),
        Ok(vec![0xc3])
    );
    // Stored at once, but not in force yet
    assert_eq!(
        h.l3(&[0x21, 0x00, 0x01]),
        Ok(vec![0xc3, 0, 0, 0, 0x02, 0xff, 0xff, 0xff])
    );
    assert_eq!(h.l3(&[0x01, 7]), Ok(vec![0xc3, 7]));
    // In force after a reboot
    assert_eq!(h.l2(0xb3, &[0x01])[0], status::REQUEST_OK);
    assert_eq!(
        h.handshake(0, LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE),
        status::REQUEST_OK
    );
    assert_eq!(h.l3(&[0x01, 7]), Ok(vec![0x01]));
}

#[test]
fn store_is_saved_only_after_changes() {
    let server = spawn_server("es-0.1.2");
    std::fs::remove_file(&server.store).unwrap();
    let mut h = Host::connect(server.port);
    assert_eq!(
        h.handshake(0, LT_SH0PRIV_ENG_SAMPLE, LT_SH0PUB_ENG_SAMPLE),
        status::REQUEST_OK
    );
    assert_eq!(h.l3(&[0x01, 3]), Ok(vec![0xc3, 3]));
    assert_eq!(h.l3(&[0x50, 16]).unwrap().len(), 20);
    assert!(
        !server.store.exists(),
        "read-only commands rewrote the store"
    );
    // R_MEM_DATA_WRITE slot 7
    assert_eq!(h.l3(&[0x40, 0x07, 0x00, 0, 0xaa]), Ok(vec![0xc3]));
    assert!(server.store.exists(), "a write was not saved");
}
