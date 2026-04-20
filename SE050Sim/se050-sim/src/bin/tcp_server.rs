/// SE050 Simulator TCP Server
///
/// Multi-threaded server: each connection gets its own T=1 responder
/// but shares the object store, matching real SE050 behavior.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use se050_sim::object_store::ObjectStore;
use se050_sim::t1::T1Responder;

const DEFAULT_PORT: u16 = 8050;

fn handle_connection(mut stream: TcpStream, store: Arc<Mutex<ObjectStore>>) {
    let peer = stream.peer_addr().unwrap();
    eprintln!("[se050-sim] Connection from {}", peer);

    stream.set_nodelay(true).ok();

    let mut t1 = T1Responder::new(0x5A);
    let mut pending_chunks: VecDeque<Vec<u8>> = VecDeque::new();

    loop {
        let mut header = [0u8; 3];
        if read_exact(&mut stream, &mut header).is_err() {
            eprintln!("[se050-sim] Connection closed by {}", peer);
            break;
        }

        let len = header[2] as usize;
        let mut payload_crc = vec![0u8; len + 2];
        if read_exact(&mut stream, &mut payload_crc).is_err() {
            eprintln!("[se050-sim] Read error from {}", peer);
            break;
        }

        let mut frame = Vec::with_capacity(3 + len + 2);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&payload_crc);

        // Process through T1Responder with locked store
        let response_chunks = {
            let mut store = store.lock().unwrap();
            t1.process_frame(&frame, &mut store)
        };

        for chunk in response_chunks {
            pending_chunks.push_back(chunk);
        }

        while pending_chunks.len() >= 2 {
            let resp_header = pending_chunks.pop_front().unwrap();
            let resp_payload_crc = pending_chunks.pop_front().unwrap();

            let mut resp_bytes = Vec::new();
            resp_bytes.extend_from_slice(&resp_header);
            resp_bytes.extend_from_slice(&resp_payload_crc);

            if stream.write_all(&resp_bytes).is_err() || stream.flush().is_err() {
                eprintln!("[se050-sim] Write error to {}", peer);
                return;
            }

            if !pending_chunks.is_empty() {
                break;
            }
        }
    }
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = stream.read(&mut buf[total..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        total += n;
    }
    Ok(())
}

fn main() {
    let port = std::env::var("SE050_SIM_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap_or_else(|e| {
        eprintln!("[se050-sim] Failed to bind port {}: {}", port, e);
        std::process::exit(1);
    });

    eprintln!("[se050-sim] Listening on port {}", port);

    let store = Arc::new(Mutex::new(ObjectStore::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let store = Arc::clone(&store);
                thread::spawn(move || handle_connection(stream, store));
            }
            Err(e) => eprintln!("[se050-sim] Accept error: {}", e),
        }
    }
}
