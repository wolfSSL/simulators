/* test_atecc608.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of ATECC608Sim.
 *
 * ATECC608Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * ATECC608Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * ATECC608A simulator SDK test suite.
 *
 * Exercises the core cryptoauthlib atcab_* API through the TCP HAL and
 * cross-verifies results against OpenSSL where that makes sense (ECDSA
 * signatures, ECDH shared secrets, SHA digests).
 */
#include "cryptoauthlib.h"
#include "hal_tcp.h"
#include "test_helpers.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

static ATCAIfaceCfg g_cfg;

static int setup(void) {
    hal_tcp_make_cfg(&g_cfg);
    if (atcab_init(&g_cfg) != ATCA_SUCCESS) {
        fprintf(stderr, "atcab_init failed\n");
        return 1;
    }
    return 0;
}

static void teardown(void) {
    atcab_release();
}

/* ===================================================================== */

static int test_info(void) {
    uint8_t rev[4] = {0};
    ASSERT_OK(atcab_info(rev));
    /* Simulator always returns 0x00 0x00 0x60 0x02 (ATECC608A marker) */
    ASSERT_EQ_INT(rev[2], 0x60);
    ASSERT_EQ_INT(rev[3], 0x02);
    return 0;
}

static int test_random(void) {
    uint8_t a[32] = {0}, b[32] = {0};
    ASSERT_OK(atcab_random(a));
    ASSERT_OK(atcab_random(b));
    if (memcmp(a, b, 32) == 0) {
        fprintf(stderr, "two randoms were identical\n");
        return 1;
    }
    int nonzero = 0;
    for (int i = 0; i < 32; ++i) if (a[i]) { nonzero = 1; break; }
    if (!nonzero) { fprintf(stderr, "random was all zeros\n"); return 1; }
    return 0;
}

static int test_sha_oneshot_matches_openssl(void) {
    const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";
    const size_t msglen = sizeof msg - 1;
    uint8_t via_sim[32] = {0};
    ASSERT_OK(atcab_sha(msglen, msg, via_sim));

    uint8_t via_openssl[32];
    SHA256(msg, msglen, via_openssl);
    ASSERT_EQ_MEM(via_sim, via_openssl, 32);
    return 0;
}

/* ECDSA-P256 sign via SE, verify independently with OpenSSL. */
static int test_ecdsa_sign_verify_openssl(void) {
    const uint16_t slot = 0;
    uint8_t pubkey[64] = {0};
    ASSERT_OK(atcab_genkey(slot, pubkey));

    uint8_t digest[32];
    for (int i = 0; i < 32; ++i) digest[i] = (uint8_t)(i * 7 + 3);

    uint8_t sig[64] = {0};
    ASSERT_OK(atcab_sign(slot, digest, sig));

    /* Rebuild an EC_KEY from the 64-byte uncompressed pubkey and verify. */
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP *grp = (EC_GROUP *)EC_KEY_get0_group(ec);
    EC_POINT *pt = EC_POINT_new(grp);
    uint8_t uncompressed[65] = { 0x04 };
    memcpy(&uncompressed[1], pubkey, 64);
    int rc = EC_POINT_oct2point(grp, pt, uncompressed, sizeof uncompressed, NULL);
    if (rc != 1) { fprintf(stderr, "oct2point failed\n"); EC_POINT_free(pt); EC_KEY_free(ec); return 1; }
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);

    ECDSA_SIG *sig_obj = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(&sig[0], 32, NULL);
    BIGNUM *s = BN_bin2bn(&sig[32], 32, NULL);
    ECDSA_SIG_set0(sig_obj, r, s);

    int v = ECDSA_do_verify(digest, sizeof digest, sig_obj, ec);
    ECDSA_SIG_free(sig_obj);
    EC_KEY_free(ec);
    if (v != 1) { fprintf(stderr, "OpenSSL ECDSA verify rejected sig\n"); return 1; }
    return 0;
}

/* SE-side verify: sign then verify-extern with the SE's own Verify command. */
static int test_ecdsa_verify_on_device(void) {
    const uint16_t slot = 0;
    uint8_t pubkey[64] = {0};
    ASSERT_OK(atcab_genkey(slot, pubkey));

    uint8_t digest[32];
    for (int i = 0; i < 32; ++i) digest[i] = (uint8_t)i;
    uint8_t sig[64] = {0};
    ASSERT_OK(atcab_sign(slot, digest, sig));

    bool is_verified = false;
    ASSERT_OK(atcab_verify_extern(digest, sig, pubkey, &is_verified));
    if (!is_verified) { fprintf(stderr, "on-device verify rejected a good sig\n"); return 1; }

    /* Negative: flip a bit in the signature, expect miscompare. */
    sig[0] ^= 0xFF;
    ASSERT_OK(atcab_verify_extern(digest, sig, pubkey, &is_verified));
    if (is_verified) { fprintf(stderr, "on-device verify accepted a bad sig\n"); return 1; }
    return 0;
}

/* ECDH symmetry: two slots, cross-derive, expect same shared secret. */
static int test_ecdh_symmetry(void) {
    uint8_t pk_a[64] = {0}, pk_b[64] = {0};
    ASSERT_OK(atcab_genkey(0, pk_a));
    ASSERT_OK(atcab_genkey(1, pk_b));
    uint8_t z_ab[32] = {0}, z_ba[32] = {0};
    ASSERT_OK(atcab_ecdh(0, pk_b, z_ab));
    ASSERT_OK(atcab_ecdh(1, pk_a, z_ba));
    ASSERT_EQ_MEM(z_ab, z_ba, 32);
    return 0;
}

/* Read-zone smoke: fetch the 32-byte block 0 of the config zone (SN + rev). */
static int test_read_config_block(void) {
    uint8_t buf[32] = {0};
    ASSERT_OK(atcab_read_zone(ATCA_ZONE_CONFIG, 0, 0, 0, buf, 32));
    /* Our simulator sets SN[0..2] = {0x01, 0x23}. */
    ASSERT_EQ_INT(buf[0], 0x01);
    ASSERT_EQ_INT(buf[1], 0x23);
    /* Revision bytes at [4..8] should mark an ATECC608A. */
    ASSERT_EQ_INT(buf[6], 0x60);
    ASSERT_EQ_INT(buf[7], 0x02);
    return 0;
}

/* is_locked: ships as locked. */
static int test_config_locked(void) {
    bool locked = false;
    ASSERT_OK(atcab_is_config_locked(&locked));
    if (!locked) { fprintf(stderr, "config zone should ship locked\n"); return 1; }
    ASSERT_OK(atcab_is_data_locked(&locked));
    if (!locked) { fprintf(stderr, "data zone should ship locked\n"); return 1; }
    return 0;
}

/* ===================================================================== */

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    if (setup() != 0) return 1;

    int passed = 0, failed = 0;
    RUN_TEST("info", test_info);
    RUN_TEST("random", test_random);
    RUN_TEST("sha256-vs-openssl", test_sha_oneshot_matches_openssl);
    RUN_TEST("ecdsa-sign-verify-openssl", test_ecdsa_sign_verify_openssl);
    RUN_TEST("ecdsa-verify-on-device", test_ecdsa_verify_on_device);
    RUN_TEST("ecdh-symmetry", test_ecdh_symmetry);
    RUN_TEST("read-config-block", test_read_config_block);
    RUN_TEST("is-locked-default", test_config_locked);

    teardown();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
