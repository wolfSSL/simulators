/* test_tropic01.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of TROPIC01Sim.
 *
 * TROPIC01Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * TROPIC01Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * TROPIC01 simulator integration smoke test.
 *
 * Drives libtropic's high-level API (the same one wolfSSL's TROPIC01
 * crypto callback hits) against the simulator over the posix/tcp HAL.
 * This validates the full stack end-to-end: TCP framing, SPI byte
 * exchange, L2 frame parse/CRC, Noise_KK1 handshake, AES-GCM L3 tunnel,
 * and every L3 command the simulator implements.
 *
 * Each test prints PASS / FAIL and the program exits non-zero on the
 * first failure so the run-test.sh wrapper surfaces it to CI.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_posix_tcp.h"
#include "psa/crypto.h"

#define PASS_OR_DIE(expr, label)                                                                  \
    do {                                                                                          \
        lt_ret_t _ret = (expr);                                                                   \
        if (_ret != LT_OK) {                                                                      \
            fprintf(stderr, "FAIL %s: %s (ret=%d)\n", (label), lt_ret_verbose(_ret), (int)_ret); \
            return -1;                                                                            \
        }                                                                                         \
        fprintf(stdout, "PASS %s\n", (label));                                                    \
    } while (0)

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 28992

static int connect_handle(lt_handle_t *h, lt_dev_posix_tcp_t *dev,
                          lt_ctx_mbedtls_v4_t *crypto_ctx) {
    const char *host = getenv("TROPIC01_SIM_HOST");
    if (!host) host = DEFAULT_HOST;
    const char *port_s = getenv("TROPIC01_SIM_PORT");
    int port = port_s ? atoi(port_s) : DEFAULT_PORT;

    memset(dev, 0, sizeof(*dev));
    dev->addr = inet_addr(host);
    dev->port = (in_port_t)port;
    h->l2.device = dev;
    h->l3.crypto_ctx = crypto_ctx;
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    fprintf(stdout, "=== TROPIC01 simulator integration test ===\n");

    if (psa_crypto_init() != PSA_SUCCESS) {
        fprintf(stderr, "FAIL psa_crypto_init\n");
        return -1;
    }

    /* PRNG seed for libtropic's host-side random_bytes (model HAL uses rand()). */
    unsigned int seed;
    if (getentropy(&seed, sizeof(seed)) != 0) {
        fprintf(stderr, "FAIL getentropy: %s\n", strerror(errno));
        return -1;
    }
    srand(seed);

    lt_handle_t lth = {0};
    lt_dev_posix_tcp_t dev;
    lt_ctx_mbedtls_v4_t crypto_ctx;
    if (connect_handle(&lth, &dev, &crypto_ctx) != 0) return -1;

    PASS_OR_DIE(lt_init(&lth), "lt_init");
    PASS_OR_DIE(lt_reboot(&lth, TR01_REBOOT), "lt_reboot");

    /* The simulator pre-provisions slot 0 with the engineering-sample
     * pairing key, so libtropic's exported sh0priv_eng_sample /
     * sh0pub_eng_sample bytes authenticate cleanly. */
    PASS_OR_DIE(lt_verify_chip_and_start_secure_session(
                    &lth, sh0priv_eng_sample, sh0pub_eng_sample,
                    TR01_PAIRING_KEY_SLOT_INDEX_0),
                "lt_verify_chip_and_start_secure_session");

    /* PING with a small payload. */
    {
        const uint8_t msg[] = "hello tropic sim";
        uint8_t reply[sizeof(msg)] = {0};
        PASS_OR_DIE(lt_ping(&lth, msg, reply, (uint16_t)sizeof(msg)), "lt_ping");
        if (memcmp(msg, reply, sizeof(msg)) != 0) {
            fprintf(stderr, "FAIL lt_ping: payload mismatch\n");
            return -1;
        }
        fprintf(stdout, "PASS lt_ping payload round-trip\n");
    }

    /* TRNG: pull 32 bytes, sanity-check non-zero. */
    {
        uint8_t random_buf[32] = {0};
        PASS_OR_DIE(lt_random_value_get(&lth, random_buf, sizeof(random_buf)),
                    "lt_random_value_get(32)");
        bool any = false;
        for (size_t i = 0; i < sizeof(random_buf); i++) {
            if (random_buf[i] != 0) {
                any = true;
                break;
            }
        }
        if (!any) {
            fprintf(stderr, "FAIL lt_random_get: all zero\n");
            return -1;
        }
        fprintf(stdout, "PASS lt_random_get non-zero\n");
    }

    /* ECC keygen + read for both curves the simulator supports. */
    {
        uint8_t pub[64] = {0};
        lt_ecc_curve_type_t curve;
        lt_ecc_key_origin_t origin;

        PASS_OR_DIE(lt_ecc_key_erase(&lth, TR01_ECC_SLOT_1), "ecc_erase pre-clean (P256)");
        PASS_OR_DIE(lt_ecc_key_generate(&lth, TR01_ECC_SLOT_1, TR01_CURVE_P256),
                    "ecc_generate P256 slot1");
        PASS_OR_DIE(lt_ecc_key_read(&lth, TR01_ECC_SLOT_1, pub, sizeof(pub), &curve, &origin),
                    "ecc_read P256 slot1");
        if (curve != TR01_CURVE_P256) {
            fprintf(stderr, "FAIL ecc_read: curve mismatch (%d)\n", (int)curve);
            return -1;
        }
        fprintf(stdout, "PASS ECC P-256 keygen+read curve=%d origin=%d\n", (int)curve, (int)origin);

        memset(pub, 0, sizeof(pub));
        PASS_OR_DIE(lt_ecc_key_erase(&lth, TR01_ECC_SLOT_2), "ecc_erase pre-clean (Ed25519)");
        PASS_OR_DIE(lt_ecc_key_generate(&lth, TR01_ECC_SLOT_2, TR01_CURVE_ED25519),
                    "ecc_generate Ed25519 slot2");
        PASS_OR_DIE(lt_ecc_key_read(&lth, TR01_ECC_SLOT_2, pub, 32, &curve, &origin),
                    "ecc_read Ed25519 slot2");
        if (curve != TR01_CURVE_ED25519) {
            fprintf(stderr, "FAIL ecc_read: curve mismatch Ed25519 (%d)\n", (int)curve);
            return -1;
        }
        fprintf(stdout, "PASS ECC Ed25519 keygen+read\n");
    }

    /* R-memory write + read round-trip into a free slot. */
    {
        const uint8_t payload[] = "TROPIC01 simulator R_MEM round-trip payload";
        const uint16_t slot = 7;
        uint8_t out[sizeof(payload)] = {0};
        uint16_t out_len = sizeof(out);
        PASS_OR_DIE(lt_r_mem_data_write(&lth, slot, payload, (uint16_t)sizeof(payload)),
                    "r_mem_data_write slot 7");
        PASS_OR_DIE(lt_r_mem_data_read(&lth, slot, out, (uint16_t)sizeof(out), &out_len),
                    "r_mem_data_read slot 7");
        if (out_len != sizeof(payload) || memcmp(out, payload, sizeof(payload)) != 0) {
            fprintf(stderr, "FAIL r_mem round-trip: out_len=%u\n", (unsigned)out_len);
            return -1;
        }
        fprintf(stdout, "PASS R_MEM data round-trip (%u bytes)\n", (unsigned)out_len);
    }

    /* Pairing-key read of slot 0 should match the host engineering key. */
    {
        uint8_t shipub_read[32] = {0};
        PASS_OR_DIE(lt_pairing_key_read(&lth, shipub_read, TR01_PAIRING_KEY_SLOT_INDEX_0),
                    "pairing_key_read slot 0");
        if (memcmp(shipub_read, sh0pub_eng_sample, sizeof(shipub_read)) != 0) {
            fprintf(stderr, "FAIL pairing_key_read: SHIPUB mismatch\n");
            return -1;
        }
        fprintf(stdout, "PASS pairing_key_read returns engineering SHIPUB\n");
    }

    PASS_OR_DIE(lt_session_abort(&lth), "lt_session_abort");
    PASS_OR_DIE(lt_deinit(&lth), "lt_deinit");
    mbedtls_psa_crypto_free();

    fprintf(stdout, "\nALL TESTS PASSED\n");
    return 0;
}
