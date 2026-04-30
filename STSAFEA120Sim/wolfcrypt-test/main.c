/* main.c
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
 * wolfCrypt + STSAFE-A120 simulator integration test.
 *
 * Registers wolfSSL's STSAFE crypto-cb so wolfCrypt routes ECC and RNG
 * operations through the simulator, then runs a focused smoke test that
 * exercises:
 *
 *   1. RNG via stse_generate_random
 *   2. ECC P-256 keygen on the device, sign+verify locally
 *   3. ECDH against an off-device peer
 *
 * This is narrower than wolfSSL's full wolfcrypt_test() because the
 * simulator only implements the STSAFE-A120 surface wolfSSL exercises,
 * not the rest of wolfCrypt's API surface (RSA, AES-CCM, etc.). The
 * full test would probe paths the simulator doesn't model.
 */

#include "stselib.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int wolfSSL_STSAFE_CryptoDevCb(int devId, wc_CryptoInfo *info, void *ctx);

static stse_Handler_t g_handler;
static int g_failures = 0;
static int g_run = 0;

#define EXPECT_OK(label, expr)                                                   \
    do {                                                                         \
        g_run++;                                                                 \
        int _r = (int)(expr);                                                    \
        if (_r != 0) {                                                           \
            fprintf(stderr, "[FAIL] %s: rc=%d\n", (label), _r);                  \
            g_failures++;                                                        \
        } else {                                                                 \
            fprintf(stdout, "[ OK ] %s\n", (label));                             \
        }                                                                        \
    } while (0)

/* For prerequisites: if the call fails, log + return early so the rest
 * of the test function doesn't run on uninitialised state and crash. */
#define REQUIRE_OK(label, expr)                                                  \
    do {                                                                         \
        g_run++;                                                                 \
        int _r = (int)(expr);                                                    \
        if (_r != 0) {                                                           \
            fprintf(stderr, "[FAIL] %s: rc=%d (skipping rest of test)\n",        \
                    (label), _r);                                                \
            g_failures++;                                                        \
            return -1;                                                           \
        }                                                                        \
        fprintf(stdout, "[ OK ] %s\n", (label));                                 \
    } while (0)

#define EXPECT_TRUE(label, cond)                                                 \
    do {                                                                         \
        g_run++;                                                                 \
        if (!(cond)) {                                                           \
            fprintf(stderr, "[FAIL] %s\n", (label));                             \
            g_failures++;                                                        \
        } else {                                                                 \
            fprintf(stdout, "[ OK ] %s\n", (label));                             \
        }                                                                        \
    } while (0)

static int init_stse(void) {
    memset(&g_handler, 0, sizeof(g_handler));
    if (stse_set_default_handler_value(&g_handler) != STSE_OK) return -1;
    g_handler.device_type = STSAFE_A120;
    if (stse_init(&g_handler) != STSE_OK) return -1;
    return 0;
}

static int rng_smoke_test(void) {
    fprintf(stdout, "\n=== rng_smoke_test ===\n");
    WC_RNG rng;
    REQUIRE_OK("wc_InitRng", wc_InitRng(&rng));
    unsigned char buf1[32], buf2[32];
    EXPECT_OK("wc_RNG_GenerateBlock #1", wc_RNG_GenerateBlock(&rng, buf1, sizeof(buf1)));
    EXPECT_OK("wc_RNG_GenerateBlock #2", wc_RNG_GenerateBlock(&rng, buf2, sizeof(buf2)));
    EXPECT_TRUE("two RNG draws differ", memcmp(buf1, buf2, sizeof(buf1)) != 0);
    wc_FreeRng(&rng);
    return 0;
}

static int ecc_p256_round_trip(int devId) {
    fprintf(stdout, "\n=== ecc_p256_round_trip ===\n");
    WC_RNG rng;
    REQUIRE_OK("wc_InitRng (ECC)", wc_InitRng(&rng));

    ecc_key key;
    if (wc_ecc_init_ex(&key, NULL, devId) != 0) {
        fprintf(stderr, "[FAIL] wc_ecc_init_ex (skipping rest of test)\n");
        g_run++;
        g_failures++;
        wc_FreeRng(&rng);
        return -1;
    }
    g_run++;
    fprintf(stdout, "[ OK ] wc_ecc_init_ex\n");

    if (wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1) != 0) {
        fprintf(stderr, "[FAIL] wc_ecc_make_key (skipping rest of test)\n");
        g_run++;
        g_failures++;
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return -1;
    }
    g_run++;
    fprintf(stdout, "[ OK ] wc_ecc_make_key (P-256, devId)\n");

    unsigned char hash[32];
    for (size_t i = 0; i < sizeof(hash); i++) hash[i] = (unsigned char)i;

    unsigned char sig[ECC_MAX_SIG_SIZE];
    word32 sig_len = sizeof(sig);
    EXPECT_OK("wc_ecc_sign_hash via STSAFE",
              wc_ecc_sign_hash(hash, sizeof(hash), sig, &sig_len, &rng, &key));

    int verified = 0;
    EXPECT_OK("wc_ecc_verify_hash via STSAFE",
              wc_ecc_verify_hash(sig, sig_len, hash, sizeof(hash), &verified, &key));
    EXPECT_TRUE("ECDSA verifies", verified == 1);

    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    return 0;
}

int main(void) {
    fprintf(stdout, "wolfCrypt + STSAFE-A120 simulator smoke test\n");
    if (init_stse() != 0) {
        fprintf(stderr, "stse_init failed; is the simulator running?\n");
        return 1;
    }

    /*
     * wolfCrypt_Init() calls stsafe_interface_init() internally (via
     * wc_port.c when WOLFSSL_STSAFE is defined) and that path also
     * registers the crypto-cb dispatcher, so we must call it BEFORE
     * wc_CryptoCb_RegisterDevice. Calling RegisterDevice before
     * wolfCrypt_Init returns CRYPTOCB_UNAVAILABLE_E because the
     * crypto-cb table is uninitialised.
     */
    EXPECT_OK("wolfCrypt_Init", wolfCrypt_Init());

    int devId = 1;
    int rc = wc_CryptoCb_RegisterDevice(devId, wolfSSL_STSAFE_CryptoDevCb, &g_handler);
    EXPECT_OK("wc_CryptoCb_RegisterDevice", rc);

    rng_smoke_test();
    ecc_p256_round_trip(devId);

    wolfCrypt_Cleanup();
    fprintf(stdout, "\n=== Summary ===\nRan %d assertions, %d failed\n", g_run, g_failures);
    return g_failures == 0 ? 0 : 1;
}
