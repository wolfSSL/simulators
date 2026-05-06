/* tcp_server.rs
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

/// TROPIC01 simulator TCP server. Speaks the "TROPIC01 Model" wire
/// protocol that libtropic's `hal/posix/tcp/` HAL talks to:
///
///   [tag (1B)] [len (2B little-endian)] [payload (len B)]
///
/// Tags (`lt_posix_tcp_tag_t`):
///   0x01 SPI_DRIVE_CSN_LOW   - empty payload, ack with same tag
///   0x02 SPI_DRIVE_CSN_HIGH  - empty payload, ack with same tag
///   0x03 SPI_SEND            - payload is MOSI bytes; reply payload is MISO
///   0x04 POWER_ON            - empty payload
///   0x05 POWER_OFF           - empty payload
///   0x06 WAIT                - 4B little-endian ms; ack
///   0x10 RESET_TARGET        - empty payload; ack
///   0xFD INVALID             - server didn't recognise the tag
///   0xFE UNSUPPORTED         - tag known but not implemented
///
/// Per-connection state: an `SpiEmulator` (CSN + SPI byte cursor) plus a
/// Noise_KK1 `Session`. The persistent `Store` is shared across all
/// connections via `Arc<Mutex<>>` -- that mirrors real silicon, where
/// the chip has a single object store.
use std::env;
use std::io::{self, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use tropic01_sim::dispatch::Dispatcher;
use tropic01_sim::object_store::Store;
use tropic01_sim::session::Session;
use tropic01_sim::spi::{SpiEmulator, SpiOutcome};
use tropic01_sim::tcp_proto::{TcpFrame, TcpTag};

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 28992;
const DEFAULT_STORE_PATH: &str = "tropic01_store.json";

fn main() -> io::Result<()> {
    let bind_addr = env::var("TROPIC01_SIM_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let port: u16 = env::var("TROPIC01_SIM_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let store_path = env::var("TROPIC01_SIM_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STORE_PATH));

    let store = if env::var_os("TROPIC01_SIM_FRESH").is_some() {
        Store::fresh()
    } else {
        Store::load_or_init(&store_path)?
    };
    let store = Arc::new(Mutex::new(store));

    let listener = TcpListener::bind((bind_addr.as_str(), port))?;
    eprintln!("[tropic01-sim] listening on {bind_addr}:{port}");

    for conn in listener.incoming() {
        let stream = conn?;
        let store = Arc::clone(&store);
        thread::spawn(move || {
            if let Err(e) = handle_connection(stream, store) {
                eprintln!("[tropic01-sim] connection error: {e}");
            }
        });
    }
    Ok(())
}

fn handle_connection(stream: TcpStream, store: Arc<Mutex<Store>>) -> io::Result<()> {
    let peer = stream.peer_addr().ok();
    eprintln!("[tropic01-sim] connection from {peer:?}");
    stream.set_nodelay(true).ok();

    // Buffer in/out independently so the borrow checker doesn't fight us.
    let stream_for_writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(stream_for_writer);

    let mut spi = SpiEmulator::new();
    let mut session = Session::new();

    while let Some(frame) = TcpFrame::read_from(&mut reader)? {
        let reply = handle_tcp_frame(&store, &mut spi, &mut session, frame)?;
        reply.write_to(&mut writer)?;
        writer.flush()?;
    }

    eprintln!("[tropic01-sim] connection closed by {peer:?}");
    Ok(())
}

fn handle_tcp_frame(
    store: &Arc<Mutex<Store>>,
    spi: &mut SpiEmulator,
    session: &mut Session,
    frame: TcpFrame,
) -> io::Result<TcpFrame> {
    let tag = TcpTag::from_u8(frame.tag);
    match tag {
        TcpTag::SpiDriveCsnLow => {
            spi.csn_low();
            Ok(TcpFrame::new(TcpTag::SpiDriveCsnLow, vec![]))
        }
        TcpTag::SpiDriveCsnHigh => {
            spi.csn_high();
            Ok(TcpFrame::new(TcpTag::SpiDriveCsnHigh, vec![]))
        }
        TcpTag::SpiSend => {
            let (miso, outcome) = spi.spi_transfer(&frame.payload);
            if matches!(outcome, SpiOutcome::RequestComplete) {
                let raw = spi.take_request();
                let mut store_lock = store.lock().unwrap();
                let response = Dispatcher::dispatch(&mut store_lock, session, &raw);
                store_lock.persist().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to persist store: {e}"),
                    )
                })?;
                drop(store_lock);
                spi.stage_response(Some(response));
            }
            Ok(TcpFrame::new(TcpTag::SpiSend, miso))
        }
        TcpTag::PowerOn | TcpTag::PowerOff => {
            // Cold boot from libtropic's perspective. Reset volatile state
            // -- session keys included -- but leave the persistent store.
            spi.csn_high();
            session.abort();
            Ok(TcpFrame::new(tag, vec![]))
        }
        TcpTag::Wait => {
            // Host requested a real-time delay (the model server sleeps);
            // we don't actually sleep -- the simulator is instant.
            Ok(TcpFrame::new(TcpTag::Wait, vec![]))
        }
        TcpTag::ResetTarget => {
            spi.csn_high();
            spi.stage_response(None);
            session.abort();
            Ok(TcpFrame::new(TcpTag::ResetTarget, vec![]))
        }
        TcpTag::Invalid | TcpTag::Unsupported => {
            // Host sent us one of its own error sentinels back -- treat
            // as a protocol error and close the connection by surfacing
            // io::ErrorKind::InvalidData.
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected client tag {:#04x}", frame.tag),
            ))
        }
    }
}
