use crate::atca::{self, status, Command};
use crate::object_store::Device;

/// Info command, mode = Revision (P1 == 0): returns the 4-byte revision
/// word stored at config[4..8]. Real ATECC608A returns `{0x00, 0x00, 0x60, 0x02}`.
pub fn handle(device: &Device, cmd: &Command) -> Vec<u8> {
    // P1 encodes the info mode. We only support Revision (0) in v1; other
    // modes (State, GPIO, etc.) fall through to parse error.
    if cmd.p1 != 0x00 {
        return atca::status_response(status::PARSE_ERROR);
    }
    let rev: [u8; 4] = device.config[4..8].try_into().unwrap();
    atca::build_response(&rev)
}
