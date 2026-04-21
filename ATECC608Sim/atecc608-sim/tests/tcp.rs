//! End-to-end TCP framing tests.
//!
//! These spin up the simulator's listen/accept loop in-process on an
//! ephemeral port and exercise the on-wire protocol: word-addressing,
//! wake response, command framing, and sleep/idle state clearing. The
//! per-command logic is already covered by `inproc.rs`; these tests only
//! verify the bytes on the wire.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use atecc608_sim::atca::WAKE_RESPONSE;
use atecc608_sim::crc::crc16_le;
use atecc608_sim::dispatch::{self, opcode};
use atecc608_sim::object_store::Store;
use atecc608_sim::session::Session;

/// A stripped-down mirror of `bin/tcp_server.rs::handle_connection` with no
/// persistence, so tests don't write JSON files to disk. Behavior must match
/// the real server: wake/idle are silent, sleep wipes volatile state.
fn serve_one(mut stream: TcpStream, store: Arc<Mutex<Store>>) {
    stream.set_nodelay(true).ok();
    let mut session = Session::new();
    let _ = WAKE_RESPONSE; // keep import alive for tests that still reference it
    loop {
        let mut wa = [0u8; 1];
        if stream.read_exact(&mut wa).is_err() {
            return;
        }
        match wa[0] {
            0x00 | 0x02 => {
                // wake / idle: silent, preserve volatile state
            }
            0x01 => session.volatile_reset(),
            0x03 => {
                let mut count = [0u8; 1];
                if stream.read_exact(&mut count).is_err() {
                    return;
                }
                let mut pkt = vec![0u8; count[0] as usize];
                pkt[0] = count[0];
                if stream.read_exact(&mut pkt[1..]).is_err() {
                    return;
                }
                let resp = {
                    let mut store = store.lock().unwrap();
                    dispatch::dispatch(&mut store.device, &mut session, &pkt)
                };
                if stream.write_all(&resp).is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

fn start_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let store = Arc::new(Mutex::new(Store::fresh()));
    let handle = thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { return };
            let store = Arc::clone(&store);
            thread::spawn(move || serve_one(stream, store));
        }
    });
    (port, handle)
}

fn make_cmd(op: u8, p1: u8, p2: u16, data: &[u8]) -> Vec<u8> {
    let count = (7 + data.len()) as u8;
    let mut pkt = vec![count, op, p1, (p2 & 0xFF) as u8, (p2 >> 8) as u8];
    pkt.extend_from_slice(data);
    pkt.extend_from_slice(&crc16_le(&pkt));
    pkt
}

fn send_cmd(stream: &mut TcpStream, op: u8, p1: u8, p2: u16, data: &[u8]) {
    let pkt = make_cmd(op, p1, p2, data);
    stream.write_all(&[0x03]).unwrap();
    stream.write_all(&pkt).unwrap();
}

fn read_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut count = [0u8; 1];
    stream.read_exact(&mut count).unwrap();
    let mut rest = vec![0u8; count[0] as usize - 1];
    stream.read_exact(&mut rest).unwrap();
    let mut out = vec![count[0]];
    out.extend(rest);
    out
}

#[test]
fn wake_is_silent() {
    // Wake (0x00) writes nothing back — it's only a bus-level pulse. The
    // server is still responsive to a follow-up command on the same
    // connection.
    let (port, _) = start_server();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_millis(100))).unwrap();
    s.write_all(&[0x00]).unwrap();
    let mut buf = [0u8; 1];
    let r = s.read(&mut buf);
    // Either 0-byte read (closed) or timeout — both confirm no bytes came
    // back. Windows/macOS differ in which error they raise for a blank
    // socket, so we just assert that if data came, it wasn't nonzero.
    match r {
        Err(_) => {}
        Ok(0) => {}
        Ok(n) => panic!("wake unexpectedly emitted {n} bytes: {:?}", &buf[..n]),
    }
}

#[test]
fn info_command_over_tcp() {
    let (port, _) = start_server();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    send_cmd(&mut s, opcode::INFO, 0x00, 0x0000, &[]);
    let r = read_response(&mut s);
    assert_eq!(r.len(), 7);
    assert_eq!(&r[1..5], &[0x00, 0x00, 0x60, 0x02]);
}

#[test]
fn idle_preserves_tempkey() {
    // Real silicon keeps volatile RAM through idle; only sleep wipes it.
    let (port, _) = start_server();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let msg = [0xCDu8; 32];
    send_cmd(&mut s, opcode::NONCE, 0x03, 0x0000, &msg);
    let r = read_response(&mut s);
    assert_eq!(r[1], 0x00);
    // Idle: no response, and TempKey should survive.
    s.write_all(&[0x02]).unwrap();
    // GenKey first so slot 0 has a private key, then Sign should succeed.
    send_cmd(&mut s, opcode::GENKEY, 0x04, 0x0000, &[]);
    let _ = read_response(&mut s);
    // Reload TempKey (GenKey may scramble it on real hardware; be explicit).
    send_cmd(&mut s, opcode::NONCE, 0x03, 0x0000, &msg);
    let r = read_response(&mut s);
    assert_eq!(r[1], 0x00);
    s.write_all(&[0x02]).unwrap();
    send_cmd(&mut s, opcode::SIGN, 0x80, 0x0000, &[]);
    let r = read_response(&mut s);
    // 67-byte signature response (count=67 = 0x43), not a 4-byte error.
    assert_eq!(r.len(), 67);
    assert_eq!(r[0], 0x43);
}

#[test]
fn sleep_clears_tempkey() {
    let (port, _) = start_server();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let msg = [0x99u8; 32];
    send_cmd(&mut s, opcode::NONCE, 0x03, 0x0000, &msg);
    let r = read_response(&mut s);
    assert_eq!(r[1], 0x00);
    s.write_all(&[0x01]).unwrap(); // sleep wipes TempKey
    send_cmd(&mut s, opcode::SIGN, 0x80, 0x0000, &[]);
    let r = read_response(&mut s);
    assert_eq!(r[1], 0x0F);
}
