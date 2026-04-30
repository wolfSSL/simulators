/* test_stsafe.c
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

/*
 * STSAFE-A120 simulator integration smoke tests.
 *
 * Drives STSELib's high-level API (the same surface wolfSSL invokes via
 * the STSAFE port) against the simulator over a TCP-mocked I2C transport,
 * and cross-verifies cryptographic results against OpenSSL where it's
 * meaningful (signing on the device, verifying off-device, and vice
 * versa; ECDH on the device, recomputing off-device).
 */

#include "stselib.h"
#include "test_helpers.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int g_failures = 0;
int g_run = 0;

static stse_Handler_t g_handler;

static void hexdump(const char *label, const unsigned char *buf, size_t n) {
    fprintf(stdout, "  %s (%zu bytes):", label, n);
    for (size_t i = 0; i < n && i < 64; i++) fprintf(stdout, " %02x", buf[i]);
    if (n > 64) fprintf(stdout, " ...");
    fprintf(stdout, "\n");
}

static int test_init(void) {
    fprintf(stdout, "\n=== test_init ===\n");
    memset(&g_handler, 0, sizeof(g_handler));
    stse_ReturnCode_t ret = stse_set_default_handler_value(&g_handler);
    ASSERT_OK("stse_set_default_handler_value", ret);
    g_handler.device_type = STSAFE_A120;
    ret = stse_init(&g_handler);
    ASSERT_OK("stse_init", ret);
    return ret == STSE_OK;
}

static int test_random(void) {
    fprintf(stdout, "\n=== test_random ===\n");
    PLAT_UI8 buf1[32], buf2[32];
    stse_ReturnCode_t ret;

    ret = stse_generate_random(&g_handler, buf1, sizeof(buf1));
    ASSERT_OK("stse_generate_random #1", ret);
    if (ret != STSE_OK) return 0;
    ret = stse_generate_random(&g_handler, buf2, sizeof(buf2));
    ASSERT_OK("stse_generate_random #2", ret);
    if (ret != STSE_OK) return 0;
    ASSERT_TRUE("two draws differ", memcmp(buf1, buf2, sizeof(buf1)) != 0);
    return 1;
}

/* P-256 helpers using OpenSSL: build EC_KEY from raw X||Y, verify a sig
 * given as raw R||S, compute SHA-256 of a buffer, etc. */
static EC_KEY *ec_key_from_raw_xy(const unsigned char *xy /* 64 bytes */) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return NULL;
    BIGNUM *bx = BN_bin2bn(xy, 32, NULL);
    BIGNUM *by = BN_bin2bn(xy + 32, 32, NULL);
    int ok = (bx && by) ? EC_KEY_set_public_key_affine_coordinates(key, bx, by) : 0;
    BN_free(bx);
    BN_free(by);
    if (!ok) {
        EC_KEY_free(key);
        return NULL;
    }
    return key;
}

static int verify_sig_with_openssl(const unsigned char *xy, const unsigned char *digest32,
                                   const unsigned char *rs64) {
    EC_KEY *key = ec_key_from_raw_xy(xy);
    if (!key) return 0;
    BIGNUM *r = BN_bin2bn(rs64, 32, NULL);
    BIGNUM *s = BN_bin2bn(rs64 + 32, 32, NULL);
    ECDSA_SIG *sig = ECDSA_SIG_new();
    int ok = sig && r && s && ECDSA_SIG_set0(sig, r, s);
    int verified = ok ? ECDSA_do_verify(digest32, 32, sig, key) == 1 : 0;
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    return verified;
}

static int test_keygen_sign_verify(void) {
    fprintf(stdout, "\n=== test_keygen_sign_verify ===\n");
    PLAT_UI8 slot = 1;
    PLAT_UI8 pub[STSE_NIST_P_256_PUBLIC_KEY_SIZE];
    memset(pub, 0, sizeof(pub));

    /*
     * `stse_generate_ecc_key_pair` writes the raw public key (point repr
     * + X length + X || Y length + Y) into pub. The point representation
     * byte (0x04) is implicit and not written by some SDK builds; we
     * pass a buffer large enough for the maximum format.
     */
    stse_ReturnCode_t ret = stse_generate_ecc_key_pair(
        &g_handler, slot, STSE_ECC_KT_NIST_P_256, /* usage_limit */ 0, pub);
    ASSERT_OK("stse_generate_ecc_key_pair P-256", ret);
    if (ret != STSE_OK) return 0;

    /*
     * The simulator returns:
     *   [point_repr 1B = 0x04]
     *   [X_len 2B = 0x0020] [X 32B]
     *   [Y_len 2B = 0x0020] [Y 32B]
     * STSELib's `pub` buffer layout differs by build flags. We extract
     * X || Y by scanning past the leading point-repr (if present) and
     * length tags.
     */
    unsigned char xy[64];
    if (pub[0] == 0x04) {
        memcpy(xy, pub + 3, 32);
        memcpy(xy + 32, pub + 37, 32);
    } else {
        /* Fallback: assume X||Y was written verbatim (no length tags). */
        memcpy(xy, pub, 64);
    }

    /* Generate a random message, hash it, ask the device to sign the digest. */
    unsigned char msg[64];
    PLAT_UI8 ret_msg[64];
    ret = stse_generate_random(&g_handler, ret_msg, sizeof(ret_msg));
    if (ret != STSE_OK) return 0;
    memcpy(msg, ret_msg, sizeof(msg));
    unsigned char digest[32];
    SHA256(msg, sizeof(msg), digest);

    PLAT_UI8 sig[STSE_NIST_P_256_SIGNATURE_R_VALUE_SIZE + STSE_NIST_P_256_SIGNATURE_S_VALUE_SIZE];
    ret = stse_ecc_generate_signature(&g_handler, slot, STSE_ECC_KT_NIST_P_256,
                                      digest, sizeof(digest), sig);
    ASSERT_OK("stse_ecc_generate_signature", ret);
    if (ret != STSE_OK) return 0;

    /* Cross-verify with OpenSSL using the public key the device returned. */
    int ossl_ok = verify_sig_with_openssl(xy, digest, sig);
    ASSERT_TRUE("OpenSSL verifies device-signed message", ossl_ok);

    /* Round trip the other way: have the device verify a signature
     * produced off-device. */
    EC_KEY *peer = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    int gen = peer && EC_KEY_generate_key(peer) == 1;
    ASSERT_TRUE("OpenSSL ephemeral keypair", gen);
    if (!gen) return 0;
    const EC_GROUP *group = EC_KEY_get0_group(peer);
    BIGNUM *bx = BN_new();
    BIGNUM *by = BN_new();
    EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(peer), bx, by, NULL);
    unsigned char peer_xy[64] = {0};
    BN_bn2binpad(bx, peer_xy, 32);
    BN_bn2binpad(by, peer_xy + 32, 32);

    ECDSA_SIG *ossl_sig = ECDSA_do_sign(digest, sizeof(digest), peer);
    ASSERT_TRUE("OpenSSL signs digest", ossl_sig != NULL);
    if (!ossl_sig) {
        EC_KEY_free(peer);
        BN_free(bx);
        BN_free(by);
        return 0;
    }
    const BIGNUM *r;
    const BIGNUM *s;
    ECDSA_SIG_get0(ossl_sig, &r, &s);
    unsigned char rs[64];
    memset(rs, 0, sizeof(rs));
    BN_bn2binpad(r, rs, 32);
    BN_bn2binpad(s, rs + 32, 32);

    PLAT_UI8 validity = 0;
    ret = stse_ecc_verify_signature(&g_handler, STSE_ECC_KT_NIST_P_256, peer_xy, rs, digest,
                                    sizeof(digest), 0, &validity);
    ASSERT_OK("stse_ecc_verify_signature", ret);
    ASSERT_TRUE("device reports OpenSSL signature valid", validity == 1);

    /* And tamper -> expect invalid. */
    rs[0] ^= 0xFF;
    ret = stse_ecc_verify_signature(&g_handler, STSE_ECC_KT_NIST_P_256, peer_xy, rs, digest,
                                    sizeof(digest), 0, &validity);
    ASSERT_OK("stse_ecc_verify_signature(tampered)", ret);
    ASSERT_TRUE("device rejects tampered sig", validity == 0);

    ECDSA_SIG_free(ossl_sig);
    EC_KEY_free(peer);
    BN_free(bx);
    BN_free(by);
    (void)hexdump;
    return 1;
}

static int test_ecdh_against_openssl(void) {
    fprintf(stdout, "\n=== test_ecdh_against_openssl ===\n");
    PLAT_UI8 slot = 1;
    PLAT_UI8 pub[STSE_NIST_P_256_PUBLIC_KEY_SIZE];
    memset(pub, 0, sizeof(pub));
    stse_ReturnCode_t ret = stse_generate_ecc_key_pair(
        &g_handler, slot, STSE_ECC_KT_NIST_P_256, 0, pub);
    ASSERT_OK("stse_generate_ecc_key_pair (ECDH)", ret);
    if (ret != STSE_OK) return 0;

    unsigned char dev_xy[64];
    if (pub[0] == 0x04) {
        memcpy(dev_xy, pub + 3, 32);
        memcpy(dev_xy + 32, pub + 37, 32);
    } else {
        memcpy(dev_xy, pub, 64);
    }

    EC_KEY *peer = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(peer);
    const EC_GROUP *group = EC_KEY_get0_group(peer);
    BIGNUM *bx = BN_new();
    BIGNUM *by = BN_new();
    EC_POINT_get_affine_coordinates(group, EC_KEY_get0_public_key(peer), bx, by, NULL);
    unsigned char peer_xy[64] = {0};
    BN_bn2binpad(bx, peer_xy, 32);
    BN_bn2binpad(by, peer_xy + 32, 32);

    /* Device-side ECDH: Establish Key */
    PLAT_UI8 dev_ss[STSE_NIST_P_256_SHARED_SECRET_SIZE];
    memset(dev_ss, 0, sizeof(dev_ss));
    ret = stse_ecc_establish_shared_secret(&g_handler, slot, STSE_ECC_KT_NIST_P_256, peer_xy, dev_ss);
    ASSERT_OK("stse_ecc_establish_shared_secret", ret);
    if (ret != STSE_OK) {
        EC_KEY_free(peer);
        BN_free(bx);
        BN_free(by);
        return 0;
    }

    /* Off-device ECDH: peer_priv * device_pub */
    EC_KEY *dev_pub_key = ec_key_from_raw_xy(dev_xy);
    unsigned char ossl_ss[32];
    int len = ECDH_compute_key(ossl_ss, sizeof(ossl_ss),
                               EC_KEY_get0_public_key(dev_pub_key), peer, NULL);
    ASSERT_TRUE("ECDH_compute_key produced 32 bytes", len == 32);

    /* Device returns: [shared_secret_len 2B][secret 32B]. Skip the leading 2 bytes. */
    const unsigned char *dev_secret = (pub[0] == 0x04 || dev_ss[0] == 0x00) ? &dev_ss[2] : dev_ss;
    ASSERT_EQ_BYTES("device ECDH matches OpenSSL", dev_secret, ossl_ss, 32);

    EC_KEY_free(peer);
    EC_KEY_free(dev_pub_key);
    BN_free(bx);
    BN_free(by);
    return 1;
}

static int test_echo(void) {
    fprintf(stdout, "\n=== test_echo ===\n");
    PLAT_UI8 in[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
                       0x89, 0xAB, 0xCD, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    PLAT_UI8 out[16] = {0};
    stse_ReturnCode_t ret = stsafea_echo(&g_handler, in, out, sizeof(in));
    ASSERT_OK("stsafea_echo", ret);
    ASSERT_EQ_BYTES("echo round-trips", in, out, sizeof(in));
    return 1;
}

int main(void) {
    fprintf(stdout, "STSAFE-A120 simulator integration smoke tests\n");

    if (!test_init()) goto done;
    test_echo();
    test_random();
    test_keygen_sign_verify();
    test_ecdh_against_openssl();

done:
    fprintf(stdout, "\n=== Summary ===\n");
    fprintf(stdout, "Ran %d assertions, %d failed\n", g_run, g_failures);
    return g_failures == 0 ? 0 : 1;
}
