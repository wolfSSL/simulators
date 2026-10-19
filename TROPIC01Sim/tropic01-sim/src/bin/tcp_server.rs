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
/// There is one simulated chip: its volatile state (`Chip`: mode, Alarm,
/// secure session, queued responses, the configuration in force) and its
/// persistent `Store` are shared by every connection, as a real chip is by
/// every host program that opens the SPI bus. A new connection is a new
/// host talking to the same powered chip; only POWER_ON, POWER_OFF and
/// RESET_TARGET reset the volatile state. The store is written to disk
/// after a command that may have changed it.
use std::env;
use std::io::{self, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use tropic01_sim::chip::Chip;
use tropic01_sim::object_store::{Provisioning, Store};
use tropic01_sim::personality::Personality;
use tropic01_sim::tcp_proto::{TcpFrame, TcpTag};

const DEFAULT_BIND: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 28992;
const DEFAULT_STORE_PATH: &str = "tropic01_store.json";

/// The simulated chip.
struct Sim {
    chip: Chip,
    store: Store,
}

fn env_flag(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok(v) if !v.is_empty() && v != "0")
}

fn main() -> io::Result<()> {
    let bind_addr = env::var("TROPIC01_SIM_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let port: u16 = env::var("TROPIC01_SIM_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let store_path = env::var("TROPIC01_SIM_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STORE_PATH));
    let personality = match env::var("TROPIC01_SIM_PERSONALITY") {
        Ok(name) => Personality::from_name(&name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown TROPIC01_SIM_PERSONALITY {name:?} (es-0.1.2, es-2.2.0, 2.2.0)"),
            )
        })?,
        Err(_) => Personality::default(),
    };
    let prov = Provisioning {
        personality,
        wolfssl_fixtures: env_flag("TROPIC01_SIM_WOLFSSL_FIXTURES"),
    };
    let busy_polls = env::var("TROPIC01_SIM_BUSY_POLLS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let store = if env_flag("TROPIC01_SIM_FRESH") {
        Store::create(&store_path, prov)?
    } else {
        Store::load_or_init(&store_path, prov)?
    };
    if env::var("TROPIC01_SIM_PERSONALITY").is_ok() && store.device.personality != personality {
        eprintln!(
            "[tropic01-sim] warning: {} was provisioned as {}, ignoring \
             TROPIC01_SIM_PERSONALITY (set TROPIC01_SIM_FRESH=1 to reprovision)",
            store_path.display(),
            store.device.personality.name()
        );
    }
    eprintln!(
        "[tropic01-sim] personality {}, store {}",
        store.device.personality.name(),
        store_path.display()
    );
    let mut chip = Chip::new(store.device.personality);
    chip.set_busy_polls(busy_polls);
    let sim = Arc::new(Mutex::new(Sim { chip, store }));

    let listener = TcpListener::bind((bind_addr.as_str(), port))?;
    eprintln!("[tropic01-sim] listening on {bind_addr}:{port}");

    for conn in listener.incoming() {
        let stream = conn?;
        let sim = Arc::clone(&sim);
        thread::spawn(move || {
            if let Err(e) = handle_connection(stream, sim) {
                eprintln!("[tropic01-sim] connection error: {e}");
            }
        });
    }
    Ok(())
}

fn handle_connection(stream: TcpStream, sim: Arc<Mutex<Sim>>) -> io::Result<()> {
    let peer = stream.peer_addr().ok();
    eprintln!("[tropic01-sim] connection from {peer:?}");
    stream.set_nodelay(true).ok();

    let stream_for_writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(stream_for_writer);

    while let Some(frame) = TcpFrame::read_from(&mut reader)? {
        let reply = handle_tcp_frame(&mut sim.lock().unwrap(), frame)?;
        reply.write_to(&mut writer)?;
        writer.flush()?;
    }

    eprintln!("[tropic01-sim] connection closed by {peer:?}");
    Ok(())
}

fn handle_tcp_frame(sim: &mut Sim, frame: TcpFrame) -> io::Result<TcpFrame> {
    let Sim { chip, store } = sim;
    let tag = TcpTag::from_u8(frame.tag);
    match tag {
        TcpTag::SpiDriveCsnLow => {
            chip.csn_low();
            Ok(TcpFrame::new(TcpTag::SpiDriveCsnLow, vec![]))
        }
        TcpTag::SpiDriveCsnHigh => {
            chip.csn_high();
            Ok(TcpFrame::new(TcpTag::SpiDriveCsnHigh, vec![]))
        }
        TcpTag::SpiSend => {
            let miso = chip.transfer(store, &frame.payload);
            if chip.take_store_dirty() {
                store.persist().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to persist store: {e}"),
                    )
                })?;
            }
            Ok(TcpFrame::new(TcpTag::SpiSend, miso))
        }
        TcpTag::PowerOn | TcpTag::PowerOff | TcpTag::ResetTarget => {
            // Volatile state (session, queued responses, Alarm mode) is
            // lost; the persistent store survives.
            chip.power_cycle();
            Ok(TcpFrame::new(tag, vec![]))
        }
        TcpTag::Wait => {
            // The simulator answers instantly, so delays need no real time.
            Ok(TcpFrame::new(TcpTag::Wait, vec![]))
        }
        TcpTag::Invalid | TcpTag::Unsupported => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected client tag {:#04x}", frame.tag),
        )),
    }
}
