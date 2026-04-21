use crate::atca::{self, status, Command};
use crate::session::Session;
use sha2::{Digest, Sha256};

/// SHA command (opcode 0x47).
///
/// P1 mode:
///   0x00 = Start    (begin a new SHA-256 context)
///   0x01 = Update   (absorb 64 bytes of data into the running context)
///   0x02 = End      (finalize, optionally absorbing trailing 0..63 bytes)
///   0x03 = Public   (single-call: hash exactly the input and return)
///
/// The ATECC608 adds a few extended modes (HMAC_START, KEY-selected HMAC,
/// etc.). wolfSSL doesn't use those for its SHA path so we treat any unknown
/// mode as a parse error.
pub fn handle(session: &mut Session, cmd: &Command) -> Vec<u8> {
    match cmd.p1 {
        0x00 => {
            session.sha.start();
            atca::status_response(status::SUCCESS)
        }
        0x01 => {
            if !session.sha.update(&cmd.data) {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            atca::status_response(status::SUCCESS)
        }
        0x02 => {
            let digest = match session.sha.finish(&cmd.data) {
                Some(d) => d,
                None => return atca::status_response(status::EXECUTION_ERROR),
            };
            atca::build_response(&digest)
        }
        0x03 => {
            let digest: [u8; 32] = Sha256::digest(&cmd.data).into();
            atca::build_response(&digest)
        }
        _ => atca::status_response(status::PARSE_ERROR),
    }
}
