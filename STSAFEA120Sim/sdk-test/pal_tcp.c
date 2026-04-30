/* pal_tcp.c
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

#include "pal_tcp.h"

#include "core/stse_platform.h"
#include "core/stse_return_codes.h"
#include "stse_conf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * Per-thread connection state. STSELib drives transactions sequentially
 * from a single thread, so a process-global socket plus a per-direction
 * staging buffer is enough.
 *
 * - tx_buf: assembled command frame (header + params + CRC). The PAL
 *   `BusSendStart` records the *advertised* total frame length, then
 *   `BusSendContinue` calls append element-by-element until
 *   `BusSendStop` flushes the buffer to the socket prepended with a
 *   2-byte big-endian length prefix.
 * - rx_buf: response frame received from the socket. `BusRecvStart`
 *   pulls the entire response (header + length + body + CRC) into the
 *   buffer, then `BusRecvContinue` / `BusRecvStop` dole it out to the
 *   caller in chunks matching the order STSELib reads in.
 */

static int g_socket = -1;
static uint8_t g_tx_buf[2048];
static size_t g_tx_len = 0;
static size_t g_tx_expected = 0;
static uint8_t g_rx_buf[2048];
static size_t g_rx_len = 0;
static size_t g_rx_pos = 0;

static const char *get_host(void) {
    const char *h = getenv("STSAFE_SIM_HOST");
    return (h && *h) ? h : "127.0.0.1";
}

static uint16_t get_port(void) {
    const char *p = getenv("STSAFE_SIM_PORT");
    if (!p || !*p) return 8120;
    long n = strtol(p, NULL, 10);
    if (n <= 0 || n > 65535) return 8120;
    return (uint16_t)n;
}

static int ensure_connected(void) {
    if (g_socket >= 0) return 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[pal_tcp] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(get_port());
    if (inet_pton(AF_INET, get_host(), &addr.sin_addr) != 1) {
        struct hostent *he = gethostbyname(get_host());
        if (!he || !he->h_addr_list[0]) {
            fprintf(stderr, "[pal_tcp] cannot resolve %s\n", get_host());
            close(sock);
            return -1;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    /* Retry connect for a short window so callers can spawn the server
     * and immediately call stse_init() without racing the listener. */
    int connected = 0;
    for (int i = 0; i < 100; i++) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            connected = 1;
            break;
        }
        struct timespec ts = {0, 20 * 1000 * 1000}; /* 20ms */
        nanosleep(&ts, NULL);
    }
    if (!connected) {
        fprintf(stderr, "[pal_tcp] connect %s:%u failed: %s\n",
                get_host(), (unsigned)get_port(), strerror(errno));
        close(sock);
        return -1;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    g_socket = sock;
    return 0;
}

static int read_exact(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t got = read(fd, p, left);
        if (got <= 0) return -1;
        p += got;
        left -= (size_t)got;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t put = write(fd, p, left);
        if (put <= 0) return -1;
        p += put;
        left -= (size_t)put;
    }
    return 0;
}

void pal_tcp_reset(void) {
    if (g_socket >= 0) {
        close(g_socket);
        g_socket = -1;
    }
    g_tx_len = 0;
    g_tx_expected = 0;
    g_rx_len = 0;
    g_rx_pos = 0;
}

/* --------------- STSELib platform initialisation hooks ----------------- */

stse_ReturnCode_t stse_platform_delay_init(void) { return STSE_OK; }
stse_ReturnCode_t stse_platform_power_init(void) { return STSE_OK; }
stse_ReturnCode_t stse_platform_crc16_init(void) { return STSE_OK; }
stse_ReturnCode_t stse_platform_crypto_init(void) { return STSE_OK; }
stse_ReturnCode_t stse_platform_generate_random_init(void) { return STSE_OK; }
stse_ReturnCode_t stse_platform_power_ctrl_init(void) { return STSE_OK; }

stse_ReturnCode_t stse_platform_power_on(PLAT_UI8 busID, PLAT_UI8 devAddr) {
    (void)busID;
    (void)devAddr;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_power_off(PLAT_UI8 busID, PLAT_UI8 devAddr) {
    (void)busID;
    (void)devAddr;
    return STSE_OK;
}

PLAT_UI32 stse_platform_generate_random(void) {
    PLAT_UI32 r;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(&r, sizeof(r), 1, f) != 1) r = (PLAT_UI32)time(NULL);
        fclose(f);
    } else {
        r = (PLAT_UI32)time(NULL);
    }
    return r;
}

void stse_platform_Delay_ms(PLAT_UI16 delay_val) {
    if (delay_val == 0) return;
    struct timespec ts;
    ts.tv_sec = delay_val / 1000;
    ts.tv_nsec = (long)(delay_val % 1000) * 1000L * 1000L;
    nanosleep(&ts, NULL);
}

/* --------------- CRC-16/X-25 (matches simulator) ----------------------- */

static uint16_t g_crc_state = 0xFFFF;

PLAT_UI16 stse_platform_Crc16_Calculate(PLAT_UI8 *pbuffer, PLAT_UI16 length) {
    uint16_t crc = 0xFFFF;
    for (PLAT_UI16 i = 0; i < length; i++) {
        crc ^= pbuffer[i];
        for (int b = 0; b < 8; b++) {
            if (crc & 1) crc = (crc >> 1) ^ 0x8408;
            else crc >>= 1;
        }
    }
    /* Stash unfinalised state for Accumulate(); finalise the return. */
    g_crc_state = crc;
    return ~crc;
}

PLAT_UI16 stse_platform_Crc16_Accumulate(PLAT_UI8 *pbuffer, PLAT_UI16 length) {
    uint16_t crc = g_crc_state;
    for (PLAT_UI16 i = 0; i < length; i++) {
        crc ^= pbuffer[i];
        for (int b = 0; b < 8; b++) {
            if (crc & 1) crc = (crc >> 1) ^ 0x8408;
            else crc >>= 1;
        }
    }
    g_crc_state = crc;
    return ~crc;
}

/* --------------- I2C transport (pipes via TCP) ------------------------- */

stse_ReturnCode_t stse_platform_i2c_init(PLAT_UI8 busID) {
    (void)busID;
    return ensure_connected() == 0 ? STSE_OK : STSE_PLATFORM_BUS_ERR;
}

stse_ReturnCode_t stse_platform_i2c_wake(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                         PLAT_UI16 speed) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                         PLAT_UI16 speed, PLAT_UI8 *pFrame,
                                         PLAT_UI16 FrameLength) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    if (ensure_connected() != 0) return STSE_PLATFORM_BUS_ERR;
    uint8_t lenbe[2] = {(uint8_t)(FrameLength >> 8), (uint8_t)FrameLength};
    if (write_exact(g_socket, lenbe, 2) != 0) return STSE_PLATFORM_BUS_ERR;
    if (write_exact(g_socket, pFrame, FrameLength) != 0) return STSE_PLATFORM_BUS_ERR;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                            PLAT_UI16 speed,
                                            PLAT_UI8 *pFrame_header,
                                            PLAT_UI8 *pFrame_payload,
                                            PLAT_UI16 *pFrame_payload_Length) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    if (ensure_connected() != 0) return STSE_PLATFORM_BUS_ERR;
    uint8_t lenbe[2];
    if (read_exact(g_socket, lenbe, 2) != 0) return STSE_PLATFORM_BUS_ERR;
    size_t total = ((size_t)lenbe[0] << 8) | lenbe[1];
    if (total < 1 || total > sizeof(g_rx_buf)) return STSE_PLATFORM_BUS_ERR;
    if (read_exact(g_socket, g_rx_buf, total) != 0) return STSE_PLATFORM_BUS_ERR;
    *pFrame_header = g_rx_buf[0];
    PLAT_UI16 cap = pFrame_payload_Length ? *pFrame_payload_Length : 0;
    PLAT_UI16 body = (PLAT_UI16)(total - 1);
    if (cap < body) body = cap;
    if (body > 0) memcpy(pFrame_payload, &g_rx_buf[1], body);
    if (pFrame_payload_Length) *pFrame_payload_Length = body;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_start(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                               PLAT_UI16 speed,
                                               PLAT_UI16 FrameLength) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    if (ensure_connected() != 0) return STSE_PLATFORM_BUS_ERR;
    if (FrameLength > sizeof(g_tx_buf)) return STSE_PLATFORM_BUS_ERR;
    g_tx_expected = FrameLength;
    g_tx_len = 0;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_continue(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                  PLAT_UI16 speed,
                                                  PLAT_UI8 *pElement,
                                                  PLAT_UI16 element_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    if (g_tx_len + element_size > sizeof(g_tx_buf)) return STSE_PLATFORM_BUS_ERR;
    if (element_size > 0 && pElement) {
        memcpy(&g_tx_buf[g_tx_len], pElement, element_size);
    }
    g_tx_len += element_size;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_stop(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                              PLAT_UI16 speed,
                                              PLAT_UI8 *pElement,
                                              PLAT_UI16 element_size) {
    if (stse_platform_i2c_send_continue(busID, devAddr, speed, pElement, element_size) != STSE_OK) {
        return STSE_PLATFORM_BUS_ERR;
    }
    if (g_tx_len != g_tx_expected) {
        fprintf(stderr,
                "[pal_tcp] tx length mismatch: expected %zu, got %zu\n",
                g_tx_expected, g_tx_len);
        return STSE_PLATFORM_BUS_ERR;
    }
    uint8_t lenbe[2] = {(uint8_t)(g_tx_len >> 8), (uint8_t)g_tx_len};
    if (write_exact(g_socket, lenbe, 2) != 0) return STSE_PLATFORM_BUS_ERR;
    if (write_exact(g_socket, g_tx_buf, g_tx_len) != 0) return STSE_PLATFORM_BUS_ERR;
    g_tx_len = 0;
    g_tx_expected = 0;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_start(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                  PLAT_UI16 speed,
                                                  PLAT_UI16 frame_Length) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    if (ensure_connected() != 0) return STSE_PLATFORM_BUS_ERR;

    /* Lazy fetch: STSELib calls receive_start twice -- once asking just
     * for the header(1) + length(2), once for the full frame including
     * those 3 bytes again. The simulator only pushes one TCP-framed
     * response per command, so we read it once and serve it across both
     * calls.
     */
    if (g_rx_len == 0) {
        uint8_t lenbe[2];
        if (read_exact(g_socket, lenbe, 2) != 0) return STSE_PLATFORM_BUS_ERR;
        size_t total = ((size_t)lenbe[0] << 8) | lenbe[1];
        if (total < 1 || total > sizeof(g_rx_buf)) return STSE_PLATFORM_BUS_ERR;
        if (read_exact(g_socket, g_rx_buf, total) != 0) return STSE_PLATFORM_BUS_ERR;
        g_rx_len = total;
        g_rx_pos = 0;
    } else {
        /* Second receive_start of the same frame -- rewind so the caller
         * can re-read the header and length. */
        g_rx_pos = 0;
    }
    (void)frame_Length;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_continue(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                     PLAT_UI16 speed,
                                                     PLAT_UI8 *pElement,
                                                     PLAT_UI16 element_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;
    if (g_rx_pos + element_size > g_rx_len) return STSE_PLATFORM_BUS_ERR;
    if (pElement && element_size > 0) {
        memcpy(pElement, &g_rx_buf[g_rx_pos], element_size);
    }
    g_rx_pos += element_size;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_stop(PLAT_UI8 busID, PLAT_UI8 devAddr,
                                                 PLAT_UI16 speed,
                                                 PLAT_UI8 *pElement,
                                                 PLAT_UI16 element_size) {
    stse_ReturnCode_t ret = stse_platform_i2c_receive_continue(busID, devAddr, speed,
                                                                pElement, element_size);
    if (g_rx_pos == g_rx_len) {
        g_rx_len = 0;
        g_rx_pos = 0;
    }
    return ret;
}

/* --------------- Crypto stubs ------------------------------------------ */

/*
 * STSELib's certificate-parsing layer references these crypto helpers. The
 * simulator's wolfCrypt smoke test does not exercise the certificate
 * authentication path, but libstse.so must still resolve them at link
 * time. Provide minimal stubs that return STSE_PLATFORM_API_NOT_SUPPORTED
 * -- if a future test actually invokes one, it will fail loudly rather
 * than silently producing garbage.
 */
stse_ReturnCode_t stse_platform_hash_compute(stse_hash_algorithm_t hash_algo,
                                             PLAT_UI8 *pPayload, PLAT_UI16 payload_length,
                                             PLAT_UI8 *pHash, PLAT_UI16 *hash_length) {
    (void)hash_algo;
    (void)pPayload;
    (void)payload_length;
    (void)pHash;
    (void)hash_length;
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

stse_ReturnCode_t stse_platform_hmac_sha256_extract(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
                                                    PLAT_UI8 *pInput_keying_material,
                                                    PLAT_UI16 input_keying_material_length,
                                                    PLAT_UI8 *pPseudorandom_key,
                                                    PLAT_UI16 pseudorandom_key_expected_length) {
    (void)pSalt;
    (void)salt_length;
    (void)pInput_keying_material;
    (void)input_keying_material_length;
    (void)pPseudorandom_key;
    (void)pseudorandom_key_expected_length;
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

stse_ReturnCode_t stse_platform_hmac_sha256_expand(PLAT_UI8 *pPseudorandom_key,
                                                   PLAT_UI16 pseudorandom_key_length,
                                                   PLAT_UI8 *pInfo, PLAT_UI16 info_length,
                                                   PLAT_UI8 *pOutput_keying_material,
                                                   PLAT_UI16 output_keying_material_length) {
    (void)pPseudorandom_key;
    (void)pseudorandom_key_length;
    (void)pInfo;
    (void)info_length;
    (void)pOutput_keying_material;
    (void)output_keying_material_length;
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

stse_ReturnCode_t stse_platform_hmac_sha256_compute(PLAT_UI8 *pSalt, PLAT_UI16 salt_length,
                                                    PLAT_UI8 *pInput_keying_material,
                                                    PLAT_UI16 input_keying_material_length,
                                                    PLAT_UI8 *pInfo, PLAT_UI16 info_length,
                                                    PLAT_UI8 *pOutput_keying_material,
                                                    PLAT_UI16 output_keying_material_length) {
    (void)pSalt;
    (void)salt_length;
    (void)pInput_keying_material;
    (void)input_keying_material_length;
    (void)pInfo;
    (void)info_length;
    (void)pOutput_keying_material;
    (void)output_keying_material_length;
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}

stse_ReturnCode_t stse_platform_ecc_verify(stse_ecc_key_type_t key_type,
                                           const PLAT_UI8 *pPubKey,
                                           PLAT_UI8 *pDigest, PLAT_UI16 digestLen,
                                           PLAT_UI8 *pSignature) {
    (void)key_type;
    (void)pPubKey;
    (void)pDigest;
    (void)digestLen;
    (void)pSignature;
    return STSE_COMMAND_CODE_NOT_SUPPORTED;
}
