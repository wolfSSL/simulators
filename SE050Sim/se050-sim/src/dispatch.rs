/* dispatch.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/// Command dispatch: routes parsed APDUs to the appropriate handler
/// based on CLA, INS (masked with 0x1F), P1, and P2.

use crate::apdu::*;
use crate::handlers;
use crate::object_store::ObjectStore;

pub fn dispatch(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    // SELECT command (CLA=0x00, INS=0xA4)
    if apdu.cla == 0x00 && apdu.ins == 0xA4 {
        return handlers::session::handle_select(apdu, store);
    }

    // All other SE050 proprietary commands use CLA=0x80 or 0x84
    if apdu.cla != 0x80 && apdu.cla != 0x84 {
        return ApduResponse::error(SW_INS_NOT_SUPPORTED);
    }

    let base_ins = apdu.base_ins();
    let cred_type = apdu.cred_type();

    match base_ins {
        INS_WRITE => match cred_type {
            P1_EC => handlers::ec::handle_write_ec_key(apdu, store),
            P1_RSA => handlers::rsa::handle_write_rsa_key(apdu, store),
            P1_AES => handlers::aes::handle_write_aes_key(apdu, store),
            P1_CRYPTO_OBJ => handlers::crypto_obj::handle_create(apdu, store),
            P1_CURVE => {
                // CreateECCurve / SetECCurveParam: our crypto libs have curves built-in
                ApduResponse::success()
            }
            P1_BINARY | P1_USERID | P1_COUNTER => {
                handlers::object_mgmt::handle_write(apdu, store)
            }
            _ => ApduResponse::error(SW_WRONG_P1P2),
        },

        INS_READ => match (cred_type, apdu.p2) {
            (P1_DEFAULT, P2_DEFAULT) if {
                // Check if Tag4 is present (RSA component read)
                let has_tag4 = apdu.parse_tlvs().map_or(false, |tlvs|
                    crate::tlv::find_tlv(&tlvs, crate::tlv::TAG_4).is_some());
                has_tag4
            } => {
                // ReadRSA: return modulus or exponent based on Tag4 component type
                let tlvs = apdu.parse_tlvs().unwrap_or_default();
                let obj_id = crate::tlv::find_tlv(&tlvs, crate::tlv::TAG_1)
                    .filter(|t| t.value.len() == 4)
                    .map(|t| { let mut id = [0u8; 4]; id.copy_from_slice(&t.value); id });
                let component = crate::tlv::find_tlv(&tlvs, crate::tlv::TAG_4)
                    .and_then(|t| t.value.first().copied())
                    .unwrap_or(0);
                match obj_id.and_then(|id| store.get(&id)) {
                    Some(crate::object_store::types::SecureObject::RSAKeyPair { private_key_der, .. }) => {
                        use rsa::pkcs1::DecodeRsaPrivateKey;
                        use rsa::traits::PublicKeyParts;
                        if let Ok(priv_key) = rsa::RsaPrivateKey::from_pkcs1_der(private_key_der) {
                            let pub_key = rsa::RsaPublicKey::from(&priv_key);
                            let data = match component {
                                0x00 => pub_key.n().to_bytes_be(), // modulus
                                0x01 => pub_key.e().to_bytes_be(), // public exponent
                                _ => return ApduResponse::error(SW_WRONG_DATA),
                            };
                            ApduResponse::success_with_tlvs(
                                &[crate::tlv::Tlv::new(crate::tlv::TAG_1, &data)])
                        } else {
                            ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED)
                        }
                    }
                    _ => ApduResponse::error(SW_FILE_NOT_FOUND),
                }
            }
            (P1_CRYPTO_OBJ, _) => handlers::crypto_obj::handle_list(apdu, store),
            (P1_CURVE, P2_ID) => {
                // EC_CurveGetId: return the curve ID for an EC key object
                let tlvs = apdu.parse_tlvs().unwrap_or_default();
                let obj_id = crate::tlv::find_tlv(&tlvs, crate::tlv::TAG_1)
                    .filter(|t| t.value.len() == 4)
                    .map(|t| { let mut id = [0u8; 4]; id.copy_from_slice(&t.value); id });
                match obj_id.and_then(|id| store.get(&id)) {
                    Some(obj) => match obj.curve_id() {
                        Some(cid) => ApduResponse::success_with_tlvs(
                            &[crate::tlv::Tlv::new(crate::tlv::TAG_1, &[cid])]),
                        None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
                    },
                    None => ApduResponse::error(SW_FILE_NOT_FOUND),
                }
            }
            (P1_CURVE, _) => {
                // ReadECCurveList: return 17-byte list marking all NIST curves as SET.
                // Index = curve_id - 1, value 0x01 = SET, 0x00 = NOT_SET.
                let mut curve_list = [0u8; 0x11]; // kSE05x_ECCurve_Total_Weierstrass_Curves
                curve_list[0x00] = 0x01; // NIST_P192
                curve_list[0x01] = 0x01; // NIST_P224
                curve_list[0x02] = 0x01; // NIST_P256
                curve_list[0x03] = 0x01; // NIST_P384
                curve_list[0x04] = 0x01; // NIST_P521
                ApduResponse::success_with_tlvs(
                    &[crate::tlv::Tlv::new(crate::tlv::TAG_1, &curve_list)])
            }
            _ => handlers::object_mgmt::handle_read(apdu, store),
        },

        INS_CRYPTO => match (cred_type, apdu.p2) {
            // Signature operations (EC + RSA share the same P1)
            (P1_SIGNATURE, P2_SIGN) => handlers::ec::handle_sign(apdu, store),
            (P1_SIGNATURE, P2_VERIFY) => handlers::ec::handle_verify(apdu, store),

            // ECDH shared secret (P2_DH=0x0F or P2_DH_REVERSE=0x59)
            (P1_EC, P2_DH) | (P1_EC, 0x59) => handlers::ec::handle_ecdh(apdu, store),

            // AES cipher oneshot
            (P1_CIPHER, P2_ENCRYPT_ONESHOT) => {
                handlers::aes::handle_encrypt_oneshot(apdu, store)
            }
            (P1_CIPHER, P2_DECRYPT_ONESHOT) => {
                handlers::aes::handle_decrypt_oneshot(apdu, store)
            }

            // AES cipher multi-step
            (P1_CIPHER, P2_ENCRYPT_INIT) | (P1_CIPHER, P2_DECRYPT_INIT) => {
                handlers::aes::handle_cipher_init(apdu, store)
            }
            (P1_CIPHER, P2_UPDATE) => handlers::aes::handle_cipher_update(apdu, store),
            (P1_CIPHER, P2_FINAL) => handlers::aes::handle_cipher_final(apdu, store),

            // RSA encrypt/decrypt
            (P1_RSA, P2_ENCRYPT_ONESHOT) => {
                handlers::rsa::handle_rsa_encrypt(apdu, store)
            }
            (P1_RSA, P2_DECRYPT_ONESHOT) => {
                handlers::rsa::handle_rsa_decrypt(apdu, store)
            }

            // Digest oneshot
            (P1_DEFAULT, P2_ONESHOT) => handlers::digest::handle_digest_oneshot(apdu, store),

            // Digest multi-step
            (P1_DEFAULT, P2_INIT) => handlers::digest::handle_digest_init(apdu, store),
            (P1_DEFAULT, P2_UPDATE) => handlers::digest::handle_digest_update(apdu, store),
            (P1_DEFAULT, P2_FINAL) => handlers::digest::handle_digest_final(apdu, store),

            _ => ApduResponse::error(SW_WRONG_P1P2),
        },

        INS_MGMT => {
            match (cred_type, apdu.p2) {
                // Crypto object management
                (P1_CRYPTO_OBJ, P2_DELETE_OBJECT) => {
                    handlers::crypto_obj::handle_delete(apdu, store)
                }
                // General management
                (_, P2_VERSION) | (_, P2_MEMORY) | (_, P2_RANDOM) | (_, P2_DELETE_ALL) => {
                    handlers::management::handle(apdu, store)
                }
                (_, P2_EXIST) | (_, P2_DELETE_OBJECT) => {
                    handlers::object_mgmt::handle_mgmt(apdu, store)
                }
                _ => ApduResponse::error(SW_WRONG_P1P2),
            }
        }

        _ => ApduResponse::error(SW_INS_NOT_SUPPORTED),
    }
}
