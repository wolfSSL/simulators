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

//! End-to-end smoke tests against the TCP server. Spawns the binary and
//! drives it the way libtropic's `hal/posix/tcp/` would: send a sequence
//! of `[tag][len LE][payload]` frames covering one CSN_LOW / SPI_SEND /
//! CSN_HIGH transaction for a write, then a poll cycle for the response.

use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use tropic01_sim::frame::{build_request, GET_RESPONSE_REQ_ID};
use tropic01_sim::tcp_proto::{TcpFrame, TcpTag};

/// RAII guard so a panicking test still kills its spawned server.
struct ServerGuard {
    child: Child,
    port: u16,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the TCP server on an unused port. Returns a guard that owns the
/// child and exposes the bound port. Sets `TROPIC01_SIM_FRESH=1` so each
/// test starts from a known-good provisioned state.
fn spawn_server() -> ServerGuard {
    let port = pick_port();
    let child = Command::new(env!("CARGO_BIN_EXE_tcp_server"))
        .env("TROPIC01_SIM_BIND", "127.0.0.1")
        .env("TROPIC01_SIM_PORT", port.to_string())
        .env("TROPIC01_SIM_FRESH", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tcp_server");
    wait_for_listen(port);
    ServerGuard { child, port }
}

fn pick_port() -> u16 {
    // Bind ephemeral, read assigned port, drop. There's a TOCTOU window
    // before the server claims it, but this is integration-test grade.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_for_listen(port: u16) {
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        sleep(Duration::from_millis(25));
    }
    panic!("tcp_server did not start listening on port {port}");
}

fn round_trip(stream: &mut TcpStream, frame: TcpFrame) -> TcpFrame {
    frame.write_to(stream).unwrap();
    TcpFrame::read_from(stream).unwrap().expect("eof from server")
}

#[test]
fn get_info_chip_id_e2e() {
    let server = spawn_server();
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();

    // Write transaction: csn_low, send GET_INFO(CHIP_ID), csn_high.
    round_trip(&mut stream, TcpFrame::new(TcpTag::SpiDriveCsnLow, vec![]));
    let req = build_request(0x01, &[0x01, 0x00]); // GET_INFO, object=CHIP_ID, block=0
    let r = round_trip(&mut stream, TcpFrame::new(TcpTag::SpiSend, req.clone()));
    assert_eq!(r.payload.len(), req.len()); // MISO bytes match MOSI length
    round_trip(&mut stream, TcpFrame::new(TcpTag::SpiDriveCsnHigh, vec![]));

    // Poll: csn_low, send 0xAA -> CHIP_STATUS=READY (0x01).
    round_trip(&mut stream, TcpFrame::new(TcpTag::SpiDriveCsnLow, vec![]));
    let status = round_trip(
        &mut stream,
        TcpFrame::new(TcpTag::SpiSend, vec![GET_RESPONSE_REQ_ID]),
    );
    assert_eq!(status.payload, vec![0x01]); // chip_status::READY

    // Read STATUS + RSP_LEN.
    let header = round_trip(&mut stream, TcpFrame::new(TcpTag::SpiSend, vec![0x00, 0x00]));
    assert_eq!(header.payload[0], 0x01); // status::REQUEST_OK
    let rsp_len = header.payload[1] as usize;
    assert_eq!(rsp_len, 128);

    // Read DATA + CRC.
    let trailer = round_trip(
        &mut stream,
        TcpFrame::new(TcpTag::SpiSend, vec![0x00; rsp_len + 2]),
    );
    assert_eq!(trailer.payload.len(), rsp_len + 2);
    // First 12 bytes of data are the chip ID; the rest are zero padding.
    let chip_id = &trailer.payload[..12];
    assert!(chip_id.iter().any(|&b| b != 0));
    round_trip(&mut stream, TcpFrame::new(TcpTag::SpiDriveCsnHigh, vec![]));

    drop(stream);
    drop(server);
}

#[test]
fn power_on_resets_chip() {
    let server = spawn_server();
    let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();

    let r = round_trip(&mut stream, TcpFrame::new(TcpTag::PowerOn, vec![]));
    assert_eq!(r.tag, TcpTag::PowerOn as u8);
    assert!(r.payload.is_empty());

    drop(stream);
    drop(server);
}
