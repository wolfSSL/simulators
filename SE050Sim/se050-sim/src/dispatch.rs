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
use crate::applet::AppletVersion;
use crate::handlers;
use crate::object_store::ObjectStore;

/// Route a plain (already-unwrapped) APDU. `scp_active` is true when this
/// command arrived over an established SCP03 channel; it gates commands whose
/// hardware behavior depends on being in an authenticated session.
pub fn dispatch(apdu: &ParsedApdu, store: &mut ObjectStore, scp_active: bool) -> ApduResponse {
    // Applet personality (SE050_SIM_APPLET env var; defaults to the
    // SE051 / applet 7.2.0 the simulator has always advertised).
    let version = AppletVersion::from_env();
    let v7 = version.is_v7();

    // SELECT command (CLA=0x00, INS=0xA4)
    if apdu.cla == 0x00 && apdu.ins == 0xA4 {
        return handlers::session::handle_select(apdu, store, version);
    }

    // All other SE050 proprietary commands use CLA=0x80. A wire CLA of 0x84
    // means SCP03 secure messaging and is unwrapped by the T=1 layer
    // (see t1.rs) before reaching here, so 0x84 is still accepted as an alias
    // for robustness (e.g. direct handler unit tests).
    if apdu.cla != 0x80 && apdu.cla != 0x84 {
        return ApduResponse::error(SW_INS_NOT_SUPPORTED);
    }

    let base_ins = apdu.base_ins();
    let cred_type = apdu.cred_type();

    match base_ins {
        INS_WRITE => match cred_type {
            P1_EC => handlers::ec::handle_write_ec_key(apdu, store, version),
            P1_RSA => handlers::rsa::handle_write_rsa_key(apdu, store, version),
            P1_AES => handlers::aes::handle_write_aes_key(apdu, store),
            P1_HMAC => handlers::aes::handle_write_hmac_key(apdu, store),
            P1_CRYPTO_OBJ => handlers::crypto_obj::handle_create(apdu, store),
            P1_CURVE => match apdu.p2 {
                P2_CREATE => handlers::curve::handle_create(apdu, store, version),
                P2_PARAM => handlers::curve::handle_set_param(apdu, store),
                _ => ApduResponse::error(SW_WRONG_P1P2),
            },
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
                if let Some(id) = obj_id {
                    if !store.policy_allows(&id, crate::policy::POLICY_OBJ_ALLOW_READ) {
                        return ApduResponse::error(SW_COMMAND_NOT_ALLOWED);
                    }
                }
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
                    _ => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
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
                    None => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
                }
            }
            (P1_CURVE, P2_LIST) => handlers::curve::handle_list(store),
            (P1_CURVE, _) => ApduResponse::error(SW_WRONG_P1P2),
            _ => handlers::object_mgmt::handle_read(apdu, store, v7),
        },

        INS_CRYPTO => match (cred_type, apdu.p2) {
            // Signature operations (EC + RSA share the same P1)
            (P1_SIGNATURE, P2_SIGN) => handlers::ec::handle_sign(apdu, store),
            (P1_SIGNATURE, P2_VERIFY) => handlers::ec::handle_verify(apdu, store),

            // ECDH shared secret (P2_DH=0x0F or P2_DH_REVERSE=0x59)
            (P1_EC, P2_DH) | (P1_EC, 0x59) => handlers::ec::handle_ecdh(
                apdu, store, handlers::ec::strict_ecdh_from_env()),

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

            // MAC (HMAC / AES-CMAC): one-shot and multi-step.
            // MACInit uses P2 = Generate (0x03) / Validate (0x44).
            (P1_MAC, P2_GENERATE_ONESHOT) => handlers::mac::handle_oneshot(apdu, store, false),
            (P1_MAC, P2_VALIDATE_ONESHOT) => handlers::mac::handle_oneshot(apdu, store, true),
            (P1_MAC, P2_GENERATE) => handlers::mac::handle_init(apdu, store, false),
            (P1_MAC, P2_MAC_VALIDATE) => handlers::mac::handle_init(apdu, store, true),
            (P1_MAC, P2_UPDATE) => handlers::mac::handle_update(apdu, store),
            (P1_MAC, P2_FINAL) => handlers::mac::handle_final(apdu, store),

            _ => ApduResponse::error(SW_WRONG_P1P2),
        },

        INS_MGMT => {
            match (cred_type, apdu.p2) {
                // Crypto object management
                (P1_CRYPTO_OBJ, P2_DELETE_OBJECT) => {
                    handlers::crypto_obj::handle_delete(apdu, store)
                }
                // EC curve deletion
                (P1_CURVE, P2_DELETE_OBJECT) => {
                    handlers::curve::handle_delete(apdu, store)
                }
                // General management
                (_, P2_VERSION) | (_, P2_MEMORY) | (_, P2_RANDOM) | (_, P2_DELETE_ALL) => {
                    handlers::management::handle(apdu, store, version)
                }
                // SetPlatformSCPRequest: only meaningful in an SCP03 session.
                (_, P2_SCP) => {
                    handlers::management::handle_set_platform_scp(apdu, store, scp_active)
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
