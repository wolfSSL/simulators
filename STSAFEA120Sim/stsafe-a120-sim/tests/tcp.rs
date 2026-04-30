/* tcp.rs
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

//! End-to-end test: spawn the `tcp_server` binary on a local port, push
//! a real STSAFE Echo command over TCP, validate the response.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use stsafe_a120_sim::frame::{build_command, status};

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

fn spawn_server() -> ServerGuard {
    // Pick a free port by binding briefly, then immediately closing.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let bin = env!("CARGO_BIN_EXE_tcp_server");
    let child = Command::new(bin)
        .env("STSAFE_SIM_BIND", "127.0.0.1")
        .env("STSAFE_SIM_PORT", port.to_string())
        .env("STSAFE_SIM_FRESH", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tcp_server");

    // Wait up to 2 seconds for the listener to come up.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return ServerGuard { child, port };
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("tcp_server failed to start on port {port}");
}

fn send_frame(port: u16, frame: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let len = (frame.len() as u16).to_be_bytes();
    s.write_all(&len).unwrap();
    s.write_all(frame).unwrap();
    let mut rlen = [0u8; 2];
    s.read_exact(&mut rlen).unwrap();
    let resp_len = u16::from_be_bytes(rlen) as usize;
    let mut resp = vec![0u8; resp_len];
    s.read_exact(&mut resp).unwrap();
    resp
}

#[test]
fn tcp_echo_round_trips() {
    let server = spawn_server();
    let payload = b"tcp echo test";
    let cmd = build_command(0x00, payload);
    let resp = send_frame(server.port, &cmd);
    assert_eq!(resp[0] & 0x1F, status::OK);
    let length = u16::from_be_bytes([resp[1], resp[2]]) as usize;
    assert_eq!(length, resp.len() - 3);
    let body = &resp[3..resp.len() - 2];
    assert_eq!(body, payload);
}

#[test]
fn tcp_random_returns_correct_size() {
    let server = spawn_server();
    let cmd = build_command(0x02, &[0x00, 64]);
    let resp = send_frame(server.port, &cmd);
    assert_eq!(resp[0] & 0x1F, status::OK);
    let body = &resp[3..resp.len() - 2];
    assert_eq!(body.len(), 64);
}
