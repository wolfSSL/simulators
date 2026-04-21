use crate::atca::{self, status, Command};
use crate::object_store::{Device, NUM_SLOTS};

/// Lock command.
///
/// P1 bit 7 clear = lock with CRC check (P2 carries a CRC of the zone we're
/// locking). Bit 7 set = lock without CRC. Bits 1-0 select the target:
///   0 = Config zone
///   1 = Data+OTP zones
///   2 = slot (slot# comes from bits 2-5 per cryptoauthlib mapping)
pub fn handle(device: &mut Device, cmd: &Command) -> Vec<u8> {
    // We intentionally skip CRC verification of the zone-to-be-locked: the
    // simulator doesn't care, and wolfSSL uses the no-CRC form anyway.
    let mode_bits = cmd.p1 & 0x03;
    match mode_bits {
        0 => {
            if device.config_locked() {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            device.set_config_locked(true);
            atca::status_response(status::SUCCESS)
        }
        1 => {
            if device.data_locked() {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            device.set_data_locked(true);
            atca::status_response(status::SUCCESS)
        }
        2 => {
            // Slot lock: slot number encoded in bits 2..5 of P1.
            let slot = ((cmd.p1 >> 2) & 0x0F) as usize;
            if slot >= NUM_SLOTS {
                return atca::status_response(status::PARSE_ERROR);
            }
            if device.slot_locked(slot) {
                return atca::status_response(status::EXECUTION_ERROR);
            }
            device.set_slot_locked(slot, true);
            atca::status_response(status::SUCCESS)
        }
        _ => atca::status_response(status::PARSE_ERROR),
    }
}
