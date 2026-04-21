use crate::atca::{self, Command};
use crate::object_store::Device;
use rand::RngCore;

/// Random command: returns 32 cryptographically random bytes regardless of
/// the Mode/UpdateSeed flags. Real silicon has knobs to skip seed update;
/// we don't model those because wolfSSL doesn't care.
pub fn handle(_device: &Device, _cmd: &Command) -> Vec<u8> {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    atca::build_response(&buf)
}
