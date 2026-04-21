/* tcp_server.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of ATECC608Sim.
 *
 * ATECC608Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * ATECC608Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// ATECC608A simulator TCP server.
///
/// Listens for TCP connections (default `127.0.0.1:8608`, overridable via
/// `ATECC608_SIM_BIND` and `ATECC608_SIM_PORT`). Each connection gets its
/// own `Session` (volatile TempKey + SHA context), but all connections
/// share the same persisted `Device` behind an `Arc<Mutex<Store>>`.
///
/// Wire framing on each connection:
///   Client -> Server: `[word_addr] ...`
///     word_addr 0x03 : command, followed by `count` byte then `count-1`
///                      bytes (the rest of the packet including CRC).
///     word_addr 0x00 : wake pulse. Silent on the protocol level —
///                      cryptoauthlib v3.7+ interleaves 0x00 with commands
///                      and does not expect a 4-byte wake response.
///                      Writing one would leave stale bytes in the socket
///                      that the next command's receive would misparse.
///                      TempKey / SHA state is preserved across wake.
///     word_addr 0x01 : sleep. Server wipes per-session volatile state,
///                      no response.
///     word_addr 0x02 : idle. Silent, preserves per-session volatile
///                      state (cryptoauthlib interleaves idle between
///                      multi-step SHA or Nonce+Sign sub-commands).
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use atecc608_sim::dispatch;
use atecc608_sim::object_store::Store;
use atecc608_sim::session::Session;

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8608;
const DEFAULT_STORE_PATH: &str = "atecc608_store.json";

fn main() -> io::Result<()> {
    let bind_addr =
        env::var("ATECC608_SIM_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let port: u16 = env::var("ATECC608_SIM_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let store_path = env::var("ATECC608_SIM_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STORE_PATH));

    let store = if env::var_os("ATECC608_SIM_FRESH").is_some() {
        Store::fresh()
    } else {
        Store::load_or_init(&store_path)?
    };
    let store = Arc::new(Mutex::new(store));

    let listener = TcpListener::bind((bind_addr.as_str(), port))?;
    eprintln!("[atecc608-sim] listening on {bind_addr}:{port}");

    for conn in listener.incoming() {
        let stream = conn?;
        let store = Arc::clone(&store);
        thread::spawn(move || {
            if let Err(e) = handle_connection(stream, store) {
                eprintln!("[atecc608-sim] connection error: {e}");
            }
        });
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, store: Arc<Mutex<Store>>) -> io::Result<()> {
    let peer = stream.peer_addr().ok();
    eprintln!("[atecc608-sim] connection from {:?}", peer);
    stream.set_nodelay(true).ok();
    let mut session = Session::new();

    loop {
        let mut word_addr = [0u8; 1];
        if stream.read_exact(&mut word_addr).is_err() {
            eprintln!("[atecc608-sim] connection closed by {:?}", peer);
            return Ok(());
        }
        match word_addr[0] {
            0x00 | 0x02 => {
                // Wake (0x00) and idle (0x02) are silent. Real silicon keeps
                // volatile RAM (TempKey, SHA context) through idle — only
                // sleep wipes them. cryptoauthlib's SHA multi-step flow and
                // Nonce+Sign flow both interleave idle word-addresses
                // between sub-commands, so preserving state across idle is
                // load-bearing.
            }
            0x01 => {
                // Sleep wipes all volatile state, matching the datasheet.
                session.volatile_reset();
            }
            0x03 => {
                let resp = read_and_dispatch(&mut stream, &store, &mut session)?;
                stream.write_all(&resp)?;
            }
            other => {
                eprintln!(
                    "[atecc608-sim] unknown word address 0x{:02X} from {:?}; closing",
                    other, peer
                );
                return Ok(());
            }
        }
    }
}

fn read_and_dispatch(
    stream: &mut TcpStream,
    store: &Arc<Mutex<Store>>,
    session: &mut Session,
) -> io::Result<Vec<u8>> {
    let mut count_byte = [0u8; 1];
    stream.read_exact(&mut count_byte)?;
    let count = count_byte[0] as usize;
    if count < 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "count byte must be >= 1",
        ));
    }
    let mut packet = vec![0u8; count];
    packet[0] = count_byte[0];
    stream.read_exact(&mut packet[1..])?;

    let mut store = store.lock().unwrap();
    let resp = dispatch(&mut store.device, session, &packet);
    store
        .persist()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to persist store: {e}")))?;
    Ok(resp)
}
