/* tcp_server.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STSAFEA120Sim.
 *
 * STSAFEA120Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STSAFEA120Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// STSAFE-A120 simulator TCP server.
///
/// Listens for TCP connections (default `127.0.0.1:8120`, overridable via
/// `STSAFE_SIM_BIND` and `STSAFE_SIM_PORT`). Each connection gets its own
/// `Session`, but all connections share the persisted `Store` behind an
/// `Arc<Mutex<>>`.
///
/// Wire framing (no I2C word-address byte -- STSELib drives the bus
/// directly without ATECC-style 0x00/0x01/0x02/0x03 prefixes):
///
///   Client -> Server (each command frame):
///     [cmd_header 1B] [length 2B BE] [body...] [crc 2B BE]
///   Server -> Client:
///     [rsp_header 1B] [length 2B BE] [body...] [crc 2B BE]
///
/// On the host SDK side, the PAL's `stse_platform_i2c_send_*` family
/// receives the *frame_length* up front (excluding the length field, but
/// including CRC) via `BusSendStart`. The PAL serializes that length as a
/// 2-byte BE prefix on the TCP stream so that the simulator can read the
/// full command frame without per-call boundary tracking.
///
/// Inbound TCP framing on this side: `[length 2B BE] [frame body]` where
/// `length` covers `[cmd_header...] [crc]`. This bracket is purely a
/// transport convenience for the TCP socket and does not exist on real
/// I2C silicon.
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use stsafe_a120_sim::dispatch;
use stsafe_a120_sim::object_store::Store;
use stsafe_a120_sim::session::Session;

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8120;
const DEFAULT_STORE_PATH: &str = "stsafe_a120_store.json";

fn main() -> io::Result<()> {
    let bind_addr = env::var("STSAFE_SIM_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let port: u16 = env::var("STSAFE_SIM_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let store_path = env::var("STSAFE_SIM_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STORE_PATH));

    let store = if env::var_os("STSAFE_SIM_FRESH").is_some() {
        Store::fresh()
    } else {
        Store::load_or_init(&store_path)?
    };
    let store = Arc::new(Mutex::new(store));

    let listener = TcpListener::bind((bind_addr.as_str(), port))?;
    eprintln!("[stsafe-a120-sim] listening on {bind_addr}:{port}");

    for conn in listener.incoming() {
        let stream = conn?;
        let store = Arc::clone(&store);
        thread::spawn(move || {
            if let Err(e) = handle_connection(stream, store) {
                eprintln!("[stsafe-a120-sim] connection error: {e}");
            }
        });
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, store: Arc<Mutex<Store>>) -> io::Result<()> {
    let peer = stream.peer_addr().ok();
    eprintln!("[stsafe-a120-sim] connection from {peer:?}");
    stream.set_nodelay(true).ok();
    let mut session = Session::new();

    loop {
        let mut len_buf = [0u8; 2];
        if let Err(e) = stream.read_exact(&mut len_buf) {
            if matches!(e.kind(), io::ErrorKind::UnexpectedEof) {
                eprintln!("[stsafe-a120-sim] connection closed by {peer:?}");
                return Ok(());
            }
            return Err(e);
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        if frame_len == 0 || frame_len > stsafe_a120_sim::frame::MAX_FRAME_LENGTH_A120 + 4 {
            eprintln!("[stsafe-a120-sim] invalid framed length {frame_len} from {peer:?}");
            return Ok(());
        }
        let mut frame = vec![0u8; frame_len];
        stream.read_exact(&mut frame)?;

        let mut store_lock = store.lock().unwrap();
        let response = dispatch(&mut store_lock, &mut session, &frame);
        store_lock.persist().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("failed to persist store: {e}"))
        })?;
        drop(store_lock);

        // Frame the response the same way: 2-byte BE length prefix then payload.
        let resp_len = response.len() as u16;
        stream.write_all(&resp_len.to_be_bytes())?;
        stream.write_all(&response)?;
    }
}
