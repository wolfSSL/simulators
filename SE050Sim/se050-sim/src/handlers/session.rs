use crate::apdu::{ApduResponse, ParsedApdu};
use crate::object_store::ObjectStore;

/// SE050 applet AID
const SE050_AID: [u8; 16] = [
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
];

/// Simulated version info: major=7, minor=2, patch=0, features=0x6FFF, securebox=0x010B
const APP_VERSION: [u8; 7] = [0x07, 0x02, 0x00, 0x6F, 0xFF, 0x01, 0x0B];

/// Handle SELECT applet command (CLA=0x00, INS=0xA4).
/// The response is raw bytes (not TLV-wrapped), matching what the driver
/// expects in receive_apdu_raw.
pub fn handle_select(apdu: &ParsedApdu, _store: &mut ObjectStore) -> ApduResponse {
    // Verify the AID matches
    if apdu.data.len() >= 16 && apdu.data[..16] == SE050_AID {
        // Return 7-byte version info + SW 0x9000
        ApduResponse::success_with_data(APP_VERSION.to_vec())
    } else {
        ApduResponse::error(0x6A82) // File not found
    }
}
