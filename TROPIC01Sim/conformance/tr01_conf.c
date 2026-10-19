/* tr01_conf.c
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
 * TROPIC01 conformance probe. The same source runs against the real chip
 * (STM32U585 wolfDemo board, SPI) and against TROPIC01Sim (POSIX, TCP), and
 * prints one line per observation:
 *
 *   T <id> ...   behavior that must match between chip and emulator
 *   I <id> ...   informational values that legitimately differ per device
 *                (FW versions, random data, keys)
 *
 * Diff the "T" lines of the two logs to find emulator fidelity issues.
 *
 * A few checks only run on application FW 2.x (strict L3 sizes): FW 0.1.2
 * handles them differently or goes into ALARM mode, and the FW 0.1.2
 * baseline was recorded before they were added.
 *
 * Only reversible operations are performed. ECC slots 29..31, R-mem slots
 * 509..511, mcounter 15 and MAC-and-Destroy slots 126..127 are used as
 * scratch space and left erased (ECC, R-mem) or re-initialized afterwards.
 * Pairing keys and the I-config are never written.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_l2.h"
#include "libtropic_l3.h"
#include "lt_crc16.h"
#include "lt_l1.h"
#include "lt_l2_frame_check.h"
#include "lt_l3_process.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hash.h"

#include "tr01_conf.h"

extern const uint8_t lt_sh0priv_eng_sample[];
extern const uint8_t lt_sh0pub_eng_sample[];
extern const uint8_t lt_sh0priv_prod0[];
extern const uint8_t lt_sh0pub_prod0[];

/* ------------------------------------------------------------------------ */
/* L1 tracing: the HAL's SPI functions are renamed to *_real at compile time
 * and wrapped here so individual transactions can be dumped. */

lt_ret_t lt_port_spi_csn_low_real(lt_l2_state_t* s2);
lt_ret_t lt_port_spi_csn_high_real(lt_l2_state_t* s2);
lt_ret_t lt_port_spi_transfer_real(lt_l2_state_t* s2, uint8_t offset,
                                   uint16_t tx_len, uint32_t timeout_ms);

static int      g_trace;
static char     g_trace_buf[2048];
static size_t   g_trace_len;

static void trace_add(const char* s)
{
    size_t n = strlen(s);
    if (g_trace_len + n + 1 < sizeof(g_trace_buf)) {
        memcpy(g_trace_buf + g_trace_len, s, n);
        g_trace_len += n;
        g_trace_buf[g_trace_len] = '\0';
    }
}

lt_ret_t lt_port_spi_csn_low(lt_l2_state_t* s2)
{
    if (g_trace) {
        trace_add(" [");
    }
    return lt_port_spi_csn_low_real(s2);
}

lt_ret_t lt_port_spi_csn_high(lt_l2_state_t* s2)
{
    if (g_trace) {
        trace_add(" ]");
    }
    return lt_port_spi_csn_high_real(s2);
}

lt_ret_t lt_port_spi_transfer(lt_l2_state_t* s2, uint8_t offset,
                              uint16_t tx_len, uint32_t timeout_ms)
{
    uint8_t  mosi[64];
    uint16_t n = tx_len > sizeof(mosi) ? sizeof(mosi) : tx_len;
    lt_ret_t ret;
    uint16_t i;
    char     tmp[16];

    memcpy(mosi, s2->buff + offset, n);
    ret = lt_port_spi_transfer_real(s2, offset, tx_len, timeout_ms);
    if (g_trace) {
        trace_add(" {");
        for (i = 0; i < n; i++) {
            snprintf(tmp, sizeof(tmp), "%02x/%02x%s", mosi[i],
                     s2->buff[offset + i], i + 1 < n ? " " : "");
            trace_add(tmp);
        }
        if (n < tx_len) {
            trace_add(" ...");
        }
        trace_add("}");
    }
    return ret;
}

static void trace_start(void)
{
    g_trace     = 1;
    g_trace_len = 0;
    g_trace_buf[0] = '\0';
}

static void trace_stop(const char* tag)
{
    g_trace = 0;
    printf("%s%s\n", tag, g_trace_buf);
}

/* ------------------------------------------------------------------------ */

static lt_handle_t        g_h;
static int                g_alarm;
static uint8_t            g_fw_major;
static uint8_t            g_stpub[32];
static int                g_fail_local;

static void hexline(const char* pfx, const uint8_t* b, size_t n)
{
    size_t i;
    printf("%s", pfx);
    for (i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static const char* rs(lt_ret_t r)
{
    return lt_ret_verbose(r);
}

/* Raw L2 request. Builds [REQ_ID][LEN][DATA][CRC], optionally corrupting the
 * CRC, writes it and reads one response frame. Prints the CHIP_STATUS, the
 * L2 STATUS, RSP_LEN and whether the response CRC is valid (nothing when id
 * is NULL). */
static lt_ret_t l2_raw(const char* id, const char* desc, uint8_t req_id,
                       const uint8_t* data, uint8_t len, int badcrc,
                       uint8_t* rsp, uint8_t* rsp_len)
{
    uint8_t* b = g_h.l2.buff;
    uint16_t crc;
    lt_ret_t ret;
    int      crcok;

    b[0] = req_id;
    b[1] = len;
    if (len) {
        memcpy(b + 2, data, len);
    }
    crc = crc16(b, len + 2);
    b[len + 2] = (uint8_t)(crc >> 8);
    b[len + 3] = (uint8_t)(crc & 0xff);
    if (badcrc) {
        b[len + 3] ^= 0x5a;
    }
    ret = lt_l1_write(&g_h.l2, (uint16_t)(len + 4), LT_L1_SPI_TIMEOUT_MS);
    if (ret != LT_OK) {
        if (id != NULL) {
            printf("T %s %s -> write %s\n", id, desc, rs(ret));
        }
        return ret;
    }
    ret = lt_l1_read(&g_h.l2, TR01_L1_LEN_MAX, LT_L1_SPI_TIMEOUT_MS);
    if (ret != LT_OK) {
        if (id != NULL) {
            printf("T %s %s -> read %s cs=%02x\n", id, desc, rs(ret), b[0]);
        }
        if (ret == LT_L1_CHIP_ALARM_MODE) {
            g_alarm = 1;
        }
        return ret;
    }
    crcok = (b[1] == TR01_L2_STATUS_REQUEST_OK || b[1] == TR01_L2_STATUS_RESULT_OK)
                ? (lt_l2_frame_check(b) == LT_OK)
                : -1;
    if (id != NULL) {
        printf("T %s %s -> cs=%02x st=%02x len=%u crc=%d\n", id, desc, b[0],
               b[1], b[2], crcok);
    }
    if (rsp != NULL && rsp_len != NULL) {
        *rsp_len = b[2];
        memcpy(rsp, b + 3, b[2]);
    }
    return LT_OK;
}

/* Raw L3 command over the open session. Prints the decrypted result byte and
 * res_size, or the L2-level failure. Returns the lt_ret of the decrypt. */
static lt_ret_t l3_raw(const char* id, const char* desc, const uint8_t* cmd,
                       uint16_t cmd_len, uint8_t* res, uint16_t* res_len)
{
    struct lt_l3_gen_frame_t* f = (struct lt_l3_gen_frame_t*)g_h.l3.buff;
    lt_ret_t ret;

    f->cmd_size = cmd_len;
    memcpy(f->data, cmd, cmd_len);
    ret = lt_l3_encrypt_request(&g_h.l3);
    if (ret == LT_OK) {
        ret = lt_l2_send_encrypted_cmd(&g_h.l2, g_h.l3.buff, sizeof(g_h.l3.buff));
    }
    if (ret != LT_OK) {
        printf("T %s %s -> send %s\n", id, desc, rs(ret));
        return ret;
    }
    ret = lt_l2_recv_encrypted_res(&g_h.l2, g_h.l3.buff, sizeof(g_h.l3.buff));
    if (ret != LT_OK) {
        printf("T %s %s -> recv %s\n", id, desc, rs(ret));
        return ret;
    }
    ret = lt_l3_decrypt_response(&g_h.l3);
    if (ret == LT_CRYPTO_ERR || ret == LT_L3_RES_SIZE_ERROR
        || ret == LT_L3_BUFFER_TOO_SMALL
        || f->cmd_size > TR01_L3_RES_CIPHERTEXT_MAX_SIZE) {
        printf("T %s %s -> decrypt %s\n", id, desc, rs(ret));
        return ret;
    }
    printf("T %s %s -> result=%02x res_size=%u\n", id, desc, f->data[0],
           f->cmd_size);
    if (res != NULL && res_len != NULL) {
        *res_len = f->cmd_size;
        memcpy(res, f->data, f->cmd_size);
    }
    return ret;
}

static lt_ret_t start_session(void)
{
    return lt_session_start(&g_h, g_stpub, TR01_PAIRING_KEY_SLOT_INDEX_0,
                            lt_sh0priv_eng_sample, lt_sh0pub_eng_sample);
}

static void ensure_session(const char* id)
{
    lt_ret_t ret;
    if (g_h.l3.session_status == LT_SECURE_SESSION_ON) {
        uint8_t p[4] = {1, 2, 3, 4}, q[4];
        ret = lt_ping(&g_h, p, q, 4);
        if (ret == LT_OK) {
            return;
        }
        printf("I %s ping before re-handshake -> %s\n", id, rs(ret));
    }
    ret = start_session();
    printf("T %s re-handshake -> %s\n", id, rs(ret));
}

/* ------------------------------------------------------------------------ */
/* Section A: L2 surface without a session */

static void section_a(void)
{
    uint8_t  d[8];
    uint8_t  rsp[256];
    uint8_t  rlen;
    lt_tr01_mode_t mode;
    lt_ret_t ret;
    int      i;
    static const uint8_t blocks[] = {0, 1, 17, 18, 28, 29, 30, 31, 255};

    ret = lt_get_tr01_mode(&g_h, &mode);
    printf("T A01 mode -> %s mode=%d\n", rs(ret), (int)mode);

    d[0] = 0x01; d[1] = 0;
    l2_raw("A02", "get_info chip_id", 0x01, d, 2, 0, rsp, &rlen);
    hexline("I A02 chip_id=", rsp, rlen);
    d[0] = 0x02;
    l2_raw("A03", "get_info riscv_fw", 0x01, d, 2, 0, rsp, &rlen);
    hexline("I A03 riscv_fw=", rsp, rlen);
    g_fw_major = (rlen == 4) ? rsp[3] : 0;
    d[0] = 0x04;
    l2_raw("A04", "get_info spect_fw", 0x01, d, 2, 0, rsp, &rlen);
    hexline("I A04 spect_fw=", rsp, rlen);
    d[0] = 0xb0; d[1] = 0x01;
    l2_raw("A05", "get_info fw_bank(1) app mode", 0x01, d, 2, 0, NULL, NULL);

    for (i = 0; i < (int)sizeof(blocks); i++) {
        char desc[48];
        d[0] = 0x00; d[1] = blocks[i];
        snprintf(desc, sizeof(desc), "get_info cert block=%u", blocks[i]);
        l2_raw("A06", desc, 0x01, d, 2, 0, rsp, &rlen);
        if (blocks[i] == 0 && rlen >= 10) {
            hexline("I A06 cert_hdr=", rsp, 10);
        }
    }

    d[1] = 0;
    d[0] = 0x03; l2_raw("A07", "get_info obj=03", 0x01, d, 2, 0, NULL, NULL);
    d[0] = 0x05; l2_raw("A07", "get_info obj=05", 0x01, d, 2, 0, NULL, NULL);
    d[0] = 0xff; l2_raw("A07", "get_info obj=ff", 0x01, d, 2, 0, NULL, NULL);

    d[0] = 0x01; d[1] = 0; d[2] = 0;
    l2_raw("A08", "get_info len=1", 0x01, d, 1, 0, NULL, NULL);
    l2_raw("A08", "get_info len=3", 0x01, d, 3, 0, NULL, NULL);
    l2_raw("A08", "get_info len=0", 0x01, d, 0, 0, NULL, NULL);

    l2_raw("A09", "req_id=77", 0x77, d, 0, 0, NULL, NULL);
    l2_raw("A09", "req_id=00", 0x00, d, 0, 0, NULL, NULL);
    l2_raw("A09", "req_id=03", 0x03, d, 0, 0, NULL, NULL);
    l2_raw("A09", "req_id=b1 (fw update data, app mode)", 0xb1, d, 0, 0, NULL,
           NULL);

    d[0] = 0x01; d[1] = 0;
    l2_raw("A10", "get_info bad crc", 0x01, d, 2, 1, NULL, NULL);
    l2_raw("A10", "resend after crc err", 0x10, d, 0, 0, NULL, NULL);

    {
        uint8_t first[256], again[256];
        uint8_t l1, l2;
        d[0] = 0x02; d[1] = 0;
        l2_raw("A11", "get_info riscv_fw", 0x01, d, 2, 0, first, &l1);
        l2_raw("A11", "resend", 0x10, d, 0, 0, again, &l2);
        printf("T A11 resend matches=%d\n",
               (l1 == l2) && memcmp(first, again, l1) == 0);
        l2_raw("A11", "resend again", 0x10, d, 0, 0, again, &l2);
        printf("T A11 resend2 matches=%d\n",
               (l1 == l2) && memcmp(first, again, l1) == 0);
        l2_raw("A11", "resend len=1", 0x10, d, 1, 0, NULL, NULL);
    }

    /* A previous host program may have left a session open on the chip */
    l2_raw(NULL, "prime: session_abt", 0x08, d, 0, 0, NULL, NULL);
    memset(rsp, 0x11, 64);
    rsp[0] = 0x01; rsp[1] = 0x00; /* cmd_size = 1 */
    l2_raw("A12", "encrypted_cmd without session", 0x04, rsp, 19, 0, NULL, NULL);
    l2_raw("A13", "session_abt without session", 0x08, d, 0, 0, NULL, NULL);
    l2_raw("A13", "session_abt len=1", 0x08, d, 1, 0, NULL, NULL);

    memset(rsp, 0x42, 64);
    rsp[32] = 1;
    l2_raw("A14", "handshake pkey=1 (empty slot)", 0x02, rsp, 33, 0, NULL, NULL);
    if (g_fw_major >= 2) {
        /* FW 0.1.2 goes into ALARM mode instead, see CONF_ALARM_TEST */
        rsp[32] = 4;
        l2_raw("A14", "handshake pkey=4 (FW 2.x)", 0x02, rsp, 33, 0, NULL,
               NULL);
    }
    rsp[32] = 0;
    l2_raw("A14", "handshake len=32", 0x02, rsp, 32, 0, NULL, NULL);
    l2_raw("A14", "handshake len=34", 0x02, rsp, 34, 0, NULL, NULL);

    d[0] = 0x00;
    l2_raw("A15", "sleep kind=00", 0x20, d, 1, 0, NULL, NULL);
    d[0] = 0x05;
    l2_raw("A15", "sleep len=0", 0x20, d, 0, 0, NULL, NULL);
    l2_raw("A15", "sleep kind=05", 0x20, d, 1, 0, NULL, NULL);
    plat_delay_ms(20);
    d[0] = 0x02; d[1] = 0;
    l2_raw("A15", "get_info after sleep", 0x01, d, 2, 0, NULL, NULL);
    l2_raw("A15", "get_info after sleep #2", 0x01, d, 2, 0, NULL, NULL);

    l2_raw("A16", "get_log", 0xa2, d, 0, 0, NULL, NULL);

    d[0] = 0x02;
    l2_raw("A17", "startup id=02", 0xb3, d, 1, 0, NULL, NULL);
    d[0] = 0x00;
    l2_raw("A17", "startup id=00", 0xb3, d, 1, 0, NULL, NULL);
    l2_raw("A17", "startup len=0", 0xb3, d, 0, 0, NULL, NULL);

    /* L1 transaction shapes */
    d[0] = 0x02; d[1] = 0;
    trace_start();
    l2_raw("A18", "traced get_info riscv_fw", 0x01, d, 2, 0, NULL, NULL);
    trace_stop("I A18 trace:");
    /* A poll with nothing pending */
    trace_start();
    ret = lt_l1_read(&g_h.l2, TR01_L1_LEN_MAX, 1);
    trace_stop("I A18 idle poll trace:");
    printf("T A18 idle poll -> %s\n", rs(ret));
}

/* ------------------------------------------------------------------------ */
/* Section B: session establishment */

static void section_b(void)
{
    static uint8_t certs[4][TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE];
    struct lt_cert_store_t store;
    uint8_t  ping_out[8] = "ping-me", ping_in[8];
    uint8_t  buf[64];
    lt_ret_t ret;
    int      i;

    memset(&store, 0, sizeof(store));
    for (i = 0; i < 4; i++) {
        store.certs[i]   = certs[i];
        store.buf_len[i] = sizeof(certs[i]);
    }
    ret = lt_get_info_cert_store(&g_h, &store);
    printf("T B01 cert_store -> %s\n", rs(ret));
    printf("I B01 cert lens %u %u %u %u\n", store.cert_len[0], store.cert_len[1],
           store.cert_len[2], store.cert_len[3]);
    hexline("I B01 cert0=", certs[0], store.cert_len[0]);
    ret = lt_get_st_pub(&store, g_stpub);
    printf("T B02 get_st_pub -> %s\n", rs(ret));
    hexline("I B02 stpub=", g_stpub, 32);

    ret = start_session();
    printf("T B03 session slot0 eng -> %s\n", rs(ret));
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T B03 ping -> %s match=%d\n", rs(ret),
           memcmp(ping_out, ping_in, sizeof(ping_out)) == 0);

    ret = start_session();
    printf("T B04 session again while open -> %s\n", rs(ret));
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T B04 ping -> %s\n", rs(ret));

    ret = lt_session_start(&g_h, g_stpub, TR01_PAIRING_KEY_SLOT_INDEX_0,
                           lt_sh0priv_prod0, lt_sh0pub_eng_sample);
    printf("T B05 session slot0 wrong shipriv -> %s\n", rs(ret));
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T B05 ping after failed handshake -> %s\n", rs(ret));

    ret = lt_session_start(&g_h, g_stpub, TR01_PAIRING_KEY_SLOT_INDEX_1,
                           lt_sh0priv_eng_sample, lt_sh0pub_eng_sample);
    printf("T B06 session slot1 (empty) -> %s\n", rs(ret));

    ret = start_session();
    printf("T B07 session slot0 eng -> %s\n", rs(ret));
    ret = lt_session_abort(&g_h);
    printf("T B07 session abort -> %s\n", rs(ret));
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T B07 ping after abort -> %s\n", rs(ret));
    memset(buf, 0x11, sizeof(buf));
    buf[0] = 0x01; buf[1] = 0x00;
    l2_raw("B07", "encrypted_cmd after abort", 0x04, buf, 19, 0, NULL, NULL);

    /* Corrupted tag: the chip should reject it and drop the session */
    ret = start_session();
    printf("T B08 session -> %s\n", rs(ret));
    memset(buf, 0x11, sizeof(buf));
    buf[0] = 0x01; buf[1] = 0x00;
    l2_raw("B08", "encrypted_cmd bad tag", 0x04, buf, 19, 0, NULL, NULL);
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T B08 ping after bad tag -> %s\n", rs(ret));

    /* Truncated L3 packet (cmd_size larger than what is sent), then abort */
    ret = start_session();
    printf("T B09 session -> %s\n", rs(ret));
    memset(buf, 0x22, sizeof(buf));
    buf[0] = 0xf4; buf[1] = 0x01; /* claims 500 bytes */
    l2_raw("B09", "encrypted_cmd partial chunk", 0x04, buf, 40, 0, NULL, NULL);
    l2_raw("B09", "session_abt", 0x08, buf, 0, 0, NULL, NULL);
    g_h.l3.session_status = LT_SECURE_SESSION_OFF;
    ret = start_session();
    printf("T B09 session after partial -> %s\n", rs(ret));
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T B09 ping -> %s\n", rs(ret));

    /* Sleep drops the session? */
    buf[0] = 0x05;
    l2_raw("B10", "sleep", 0x20, buf, 1, 0, NULL, NULL);
    plat_delay_ms(20);
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T B10 ping after sleep -> %s\n", rs(ret));
    g_h.l3.session_status = LT_SECURE_SESSION_OFF;
    ret = start_session();
    printf("T B10 session after sleep -> %s\n", rs(ret));
}

/* ------------------------------------------------------------------------ */
/* Section C: L3 commands */

static void c_ping(void)
{
    static uint8_t out[4096], in[4096];
    static const uint16_t lens[] = {1, 2, 100, 235, 236, 237, 488, 1000, 4096};
    uint8_t  cmd[8];
    uint8_t  res[16];
    uint16_t res_len;
    lt_ret_t ret;
    int      i;

    for (i = 0; i < (int)sizeof(out); i++) {
        out[i] = (uint8_t)(i * 7 + 3);
    }
    for (i = 0; i < (int)(sizeof(lens) / sizeof(lens[0])); i++) {
        memset(in, 0, lens[i]);
        ret = lt_ping(&g_h, out, in, lens[i]);
        printf("T C01 ping len=%u -> %s match=%d\n", lens[i], rs(ret),
               memcmp(out, in, lens[i]) == 0);
    }
    cmd[0] = 0x01;
    l3_raw("C01", "ping len=0", cmd, 1, res, &res_len);
}

static void c_unknown(void)
{
    static const uint8_t ids[] = {0x00, 0x02, 0x13, 0x23, 0x32, 0x43, 0x51,
                                  0x64, 0x72, 0x83, 0x91, 0xa0, 0xa1, 0xa2,
                                  0xa3, 0xa4, 0xa5, 0xb0, 0xff};
    uint8_t  cmd[48];
    uint8_t  res[64];
    uint16_t res_len;
    int      i;
    char     desc[32];

    memset(cmd, 0, sizeof(cmd));
    for (i = 0; i < (int)sizeof(ids); i++) {
        cmd[0] = ids[i];
        snprintf(desc, sizeof(desc), "cmd_id=%02x", ids[i]);
        if (l3_raw("C02", desc, cmd, 4, res, &res_len) != LT_OK) {
            ensure_session("C02");
        }
    }
}

static void c_random(void)
{
    uint8_t  cmd[4];
    static uint8_t res[300];
    uint16_t res_len;
    uint8_t  rnd[255];
    lt_ret_t ret;

    ret = lt_random_value_get(&g_h, rnd, 32);
    printf("T C03 random 32 -> %s\n", rs(ret));
    hexline("I C03 rnd=", rnd, 32);
    ret = lt_random_value_get(&g_h, rnd, 255);
    printf("T C03 random 255 -> %s\n", rs(ret));
    cmd[0] = 0x50; cmd[1] = 0;
    l3_raw("C03", "random n=0", cmd, 2, res, &res_len);
    cmd[1] = 1;
    l3_raw("C03", "random n=1", cmd, 2, res, &res_len);
    cmd[1] = 255;
    l3_raw("C03", "random n=255", cmd, 2, res, &res_len);
    cmd[1] = 4; cmd[2] = 0;
    if (l3_raw("C03", "random cmd_size=3", cmd, 3, res, &res_len) != LT_OK) {
        ensure_session("C03");
    }
    if (l3_raw("C03", "random cmd_size=1", cmd, 1, res, &res_len) != LT_OK) {
        ensure_session("C03");
    }
}

static void c_pairing(void)
{
    uint8_t  pub[32];
    uint8_t  cmd[8];
    uint8_t  res[64];
    uint16_t res_len;
    lt_ret_t ret;
    int      i;
    char     desc[32];

    for (i = 0; i < 4; i++) {
        ret = lt_pairing_key_read(&g_h, pub, (lt_pkey_index_t)i);
        printf("T C04 pairing_key_read %d -> %s\n", i, rs(ret));
        if (ret == LT_OK) {
            printf("T C04 pairing_key %d is eng sample=%d\n", i,
                   memcmp(pub, lt_sh0pub_eng_sample, 32) == 0);
        }
    }
    for (i = 0; i < 3; i++) {
        static const uint16_t slots[] = {1, 4, 0x0100};
        cmd[0] = 0x11;
        cmd[1] = (uint8_t)(slots[i] & 0xff);
        cmd[2] = (uint8_t)(slots[i] >> 8);
        snprintf(desc, sizeof(desc), "pairing_key_read raw slot=%u", slots[i]);
        if (l3_raw("C04", desc, cmd, 3, res, &res_len) != LT_OK) {
            ensure_session("C04");
        }
    }
    /* Invalidate / write of a non-existent slot index only (no state change) */
    cmd[0] = 0x12; cmd[1] = 4; cmd[2] = 0;
    if (l3_raw("C04", "pairing_key_invalidate slot=4", cmd, 3, res, &res_len)
            != LT_OK) {
        ensure_session("C04");
    }
}

static void c_config(void)
{
    struct lt_config_t cfg;
    uint8_t  cmd[8];
    uint8_t  res[16];
    uint16_t res_len;
    lt_ret_t ret;
    int      i;
    static const uint16_t addrs[] = {0x0002, 0x00fc, 0x0200, 0x0204, 0xffff};
    char     desc[48];

    ret = lt_read_whole_R_config(&g_h, &cfg);
    printf("T C05 r_config read all -> %s\n", rs(ret));
    for (i = 0; i < LT_CONFIG_OBJ_CNT && ret == LT_OK; i++) {
        printf("I C05 R %-40s %08" PRIx32 "\n", cfg_desc_table[i].desc,
               cfg.obj[i]);
    }
    ret = lt_read_whole_I_config(&g_h, &cfg);
    printf("T C05 i_config read all -> %s\n", rs(ret));
    for (i = 0; i < LT_CONFIG_OBJ_CNT && ret == LT_OK; i++) {
        printf("I C05 I %-40s %08" PRIx32 "\n", cfg_desc_table[i].desc,
               cfg.obj[i]);
    }
    for (i = 0; i < (int)(sizeof(addrs) / sizeof(addrs[0])); i++) {
        cmd[0] = 0x21;
        cmd[1] = (uint8_t)(addrs[i] & 0xff);
        cmd[2] = (uint8_t)(addrs[i] >> 8);
        snprintf(desc, sizeof(desc), "r_config_read raw addr=%04x", addrs[i]);
        if (l3_raw("C05", desc, cmd, 3, res, &res_len) != LT_OK) {
            ensure_session("C05");
        }
        cmd[0] = 0x31;
        snprintf(desc, sizeof(desc), "i_config_read raw addr=%04x", addrs[i]);
        if (l3_raw("C05", desc, cmd, 3, res, &res_len) != LT_OK) {
            ensure_session("C05");
        }
    }
}

/* RFC 8032 test vector 1 */
static const uint8_t ed_sk1[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
    0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
static const uint8_t ed_pk1[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
    0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
static const uint8_t ed_sig1[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc,
    0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15,
    0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
    0x8e, 0x7a, 0x10, 0x0b};
/* RFC 6979 A.2.5 P-256 key */
static const uint8_t p256_d[32] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57,
    0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
    0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};
static const uint8_t p256_q[64] = {
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74,
    0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
    0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10,
    0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94,
    0xd4, 0x46, 0x22, 0x99};
static const uint8_t p256_n[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

static int verify_p256(const uint8_t* q, const uint8_t* hash,
                       const uint8_t* rs64)
{
    ecc_key key;
    mp_int  r, s;
    int     ok = 0;
    int     ret;

    wc_ecc_init(&key);
    ret = wc_ecc_import_unsigned(&key, q, q + 32, NULL, ECC_SECP256R1);
    if (ret == 0) {
        mp_init(&r);
        mp_init(&s);
        mp_read_unsigned_bin(&r, rs64, 32);
        mp_read_unsigned_bin(&s, rs64 + 32, 32);
        ret = wc_ecc_verify_hash_ex(&r, &s, hash, 32, &ok, &key);
        if (ret != 0) {
            ok = 0;
        }
        mp_clear(&r);
        mp_clear(&s);
    }
    wc_ecc_free(&key);
    return ok;
}

static int verify_ed(const uint8_t* pk, const uint8_t* msg, uint32_t msg_len,
                     const uint8_t* sig)
{
    ed25519_key key;
    int         ok = 0;

    wc_ed25519_init(&key);
    if (wc_ed25519_import_public(pk, 32, &key) == 0) {
        if (wc_ed25519_verify_msg(sig, 64, msg, msg_len, &ok, &key) != 0) {
            ok = 0;
        }
    }
    wc_ed25519_free(&key);
    return ok;
}

static int p256_on_curve(const uint8_t* q)
{
    ecc_key key;
    int     ok;

    wc_ecc_init(&key);
    ok = (wc_ecc_import_unsigned(&key, q, q + 32, NULL, ECC_SECP256R1) == 0)
         && (wc_ecc_check_key(&key) == 0);
    wc_ecc_free(&key);
    return ok;
}

static void c_ecc(void)
{
    static uint8_t msg[4096];
    uint8_t  pub[64];
    uint8_t  sig[64], sig2[64];
    uint8_t  hash[32];
    uint8_t  cmd[64];
    uint8_t  res[96];
    uint16_t res_len;
    lt_ecc_curve_type_t curve;
    lt_ecc_key_origin_t origin;
    lt_ret_t ret;
    int      i;
    static const uint16_t edlens[] = {1, 64, 200, 4000, 4096};
    const lt_ecc_slot_t S = TR01_ECC_SLOT_31;

    for (i = 0; i < (int)sizeof(msg); i++) {
        msg[i] = (uint8_t)(i ^ 0x5a);
    }
    wc_Sha256Hash((const byte*)"sample", 6, hash);

    /* clean slate */
    for (i = 29; i <= 31; i++) {
        (void)lt_ecc_key_erase(&g_h, (lt_ecc_slot_t)i);
    }

    ret = lt_ecc_key_read(&g_h, S, pub, sizeof(pub), &curve, &origin);
    printf("T C06 read empty -> %s\n", rs(ret));
    cmd[0] = 0x62; cmd[1] = 31; cmd[2] = 0;
    l3_raw("C06", "read empty raw", cmd, 3, res, &res_len);
    ret = lt_ecc_key_erase(&g_h, S);
    printf("T C06 erase empty -> %s\n", rs(ret));
    ret = lt_ecc_ecdsa_sign(&g_h, S, hash, 32, sig);
    printf("T C06 ecdsa empty -> %s\n", rs(ret));
    ret = lt_ecc_eddsa_sign(&g_h, S, msg, 16, sig);
    printf("T C06 eddsa empty -> %s\n", rs(ret));

    /* P-256 generate */
    ret = lt_ecc_key_generate(&g_h, S, TR01_CURVE_P256);
    printf("T C06 gen p256 -> %s\n", rs(ret));
    ret = lt_ecc_key_read(&g_h, S, pub, sizeof(pub), &curve, &origin);
    printf("T C06 read p256 -> %s curve=%d origin=%d oncurve=%d\n", rs(ret),
           (int)curve, (int)origin, p256_on_curve(pub));
    cmd[0] = 0x62; cmd[1] = 31; cmd[2] = 0;
    l3_raw("C06", "read p256 raw", cmd, 3, res, &res_len);
    ret = lt_ecc_key_generate(&g_h, S, TR01_CURVE_P256);
    printf("T C06 gen p256 occupied -> %s\n", rs(ret));
    ret = lt_ecc_key_generate(&g_h, S, TR01_CURVE_ED25519);
    printf("T C06 gen ed25519 occupied -> %s\n", rs(ret));
    ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_P256, p256_d);
    printf("T C06 store occupied -> %s\n", rs(ret));
    ret = lt_ecc_ecdsa_sign(&g_h, S, hash, 32, sig);
    printf("T C06 ecdsa -> %s verify=%d\n", rs(ret), verify_p256(pub, hash, sig));
    ret = lt_ecc_ecdsa_sign(&g_h, S, hash, 32, sig2);
    printf("T C06 ecdsa again -> %s verify=%d same_sig=%d\n", rs(ret),
           verify_p256(pub, hash, sig2), memcmp(sig, sig2, 64) == 0);
    ret = lt_ecc_eddsa_sign(&g_h, S, msg, 16, sig);
    printf("T C06 eddsa on p256 -> %s\n", rs(ret));
    ret = lt_ecc_key_erase(&g_h, S);
    printf("T C06 erase -> %s\n", rs(ret));
    ret = lt_ecc_key_read(&g_h, S, pub, sizeof(pub), &curve, &origin);
    printf("T C06 read after erase -> %s\n", rs(ret));

    /* Ed25519 generate */
    ret = lt_ecc_key_generate(&g_h, S, TR01_CURVE_ED25519);
    printf("T C06 gen ed25519 -> %s\n", rs(ret));
    ret = lt_ecc_key_read(&g_h, S, pub, sizeof(pub), &curve, &origin);
    printf("T C06 read ed25519 -> %s curve=%d origin=%d\n", rs(ret), (int)curve,
           (int)origin);
    l3_raw("C06", "read ed25519 raw", cmd, 3, res, &res_len);
    for (i = 0; i < (int)(sizeof(edlens) / sizeof(edlens[0])); i++) {
        ret = lt_ecc_eddsa_sign(&g_h, S, msg, edlens[i], sig);
        printf("T C06 eddsa len=%u -> %s verify=%d\n", edlens[i], rs(ret),
               verify_ed(pub, msg, edlens[i], sig));
    }
    ret = lt_ecc_eddsa_sign(&g_h, S, msg, 64, sig2);
    (void)lt_ecc_eddsa_sign(&g_h, S, msg, 64, sig);
    printf("T C06 eddsa deterministic=%d\n", memcmp(sig, sig2, 64) == 0);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x71; cmd[1] = 31;
    l3_raw("C06", "eddsa raw len=0", cmd, 16, res, &res_len);
    if (res_len == 80) {
        printf("T C06 eddsa len=0 verify=%d\n", verify_ed(pub, msg, 0, res + 16));
    }
    ret = lt_ecc_ecdsa_sign(&g_h, S, hash, 32, sig);
    printf("T C06 ecdsa on ed25519 -> %s\n", rs(ret));
    ret = lt_ecc_key_erase(&g_h, S);
    printf("T C06 erase -> %s\n", rs(ret));

    /* Stored keys with known vectors */
    ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_ED25519, ed_sk1);
    printf("T C06 store ed25519 rfc8032 -> %s\n", rs(ret));
    ret = lt_ecc_key_read(&g_h, S, pub, sizeof(pub), &curve, &origin);
    printf("T C06 read stored ed25519 -> %s curve=%d origin=%d pubmatch=%d\n",
           rs(ret), (int)curve, (int)origin, memcmp(pub, ed_pk1, 32) == 0);
    l3_raw("C06", "eddsa raw len=0 (rfc8032 tv1)", cmd, 16, res, &res_len);
    if (res_len == 80) {
        printf("T C06 eddsa tv1 sig matches rfc8032=%d\n",
               memcmp(res + 16, ed_sig1, 64) == 0);
    }
    ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_ED25519, ed_sk1);
    printf("T C06 store ed25519 occupied -> %s\n", rs(ret));
    ret = lt_ecc_key_erase(&g_h, S);
    printf("T C06 erase -> %s\n", rs(ret));

    ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_P256, p256_d);
    printf("T C06 store p256 rfc6979 -> %s\n", rs(ret));
    ret = lt_ecc_key_read(&g_h, S, pub, sizeof(pub), &curve, &origin);
    printf("T C06 read stored p256 -> %s curve=%d origin=%d pubmatch=%d\n",
           rs(ret), (int)curve, (int)origin, memcmp(pub, p256_q, 64) == 0);
    ret = lt_ecc_ecdsa_sign(&g_h, S, hash, 32, sig);
    printf("T C06 ecdsa stored -> %s verify=%d\n", rs(ret),
           verify_p256(p256_q, hash, sig));
    hexline("I C06 ecdsa r=", sig, 32);
    ret = lt_ecc_key_erase(&g_h, S);
    printf("T C06 erase -> %s\n", rs(ret));

    /* Invalid private scalars */
    {
        uint8_t k[32];
        memset(k, 0, sizeof(k));
        ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_P256, k);
        printf("T C06 store p256 k=0 -> %s\n", rs(ret));
        (void)lt_ecc_key_erase(&g_h, S);
        ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_P256, p256_n);
        printf("T C06 store p256 k=n -> %s\n", rs(ret));
        (void)lt_ecc_key_erase(&g_h, S);
        memset(k, 0xff, sizeof(k));
        ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_P256, k);
        printf("T C06 store p256 k=ff..ff -> %s\n", rs(ret));
        (void)lt_ecc_key_erase(&g_h, S);
        memset(k, 0, sizeof(k));
        ret = lt_ecc_key_store(&g_h, S, TR01_CURVE_ED25519, k);
        printf("T C06 store ed25519 k=0 -> %s\n", rs(ret));
        (void)lt_ecc_key_erase(&g_h, S);
    }

    /* Raw malformed commands */
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x60; cmd[1] = 31; cmd[3] = 0x00;
    l3_raw("C06", "gen curve=0", cmd, 4, res, &res_len);
    cmd[3] = 0x03;
    l3_raw("C06", "gen curve=3", cmd, 4, res, &res_len);
    cmd[1] = 32; cmd[3] = 0x01;
    l3_raw("C06", "gen slot=32", cmd, 4, res, &res_len);
    cmd[0] = 0x62;
    l3_raw("C06", "read slot=32", cmd, 3, res, &res_len);
    cmd[0] = 0x63;
    l3_raw("C06", "erase slot=32", cmd, 3, res, &res_len);
    cmd[0] = 0x70;
    l3_raw("C06", "ecdsa slot=32", cmd, 48, res, &res_len);
    cmd[0] = 0x71;
    l3_raw("C06", "eddsa slot=32", cmd, 16, res, &res_len);
    cmd[0] = 0x61; cmd[1] = 31; cmd[3] = 0x03;
    l3_raw("C06", "store curve=3", cmd, 48, res, &res_len);
    cmd[0] = 0x62; cmd[1] = 0x1f; cmd[2] = 0x01;
    l3_raw("C06", "read slot=0x11f", cmd, 3, res, &res_len);
    cmd[0] = 0x60; cmd[1] = 31; cmd[2] = 0; cmd[3] = 0x01;
    if (l3_raw("C06", "gen cmd_size=5", cmd, 5, res, &res_len) != LT_OK) {
        ensure_session("C06");
    }
    (void)lt_ecc_key_erase(&g_h, S);
    cmd[0] = 0x70;
    if (l3_raw("C06", "ecdsa cmd_size=47", cmd, 47, res, &res_len) != LT_OK) {
        ensure_session("C06");
    }
    if (l3_raw("C06", "ecdsa cmd_size=49", cmd, 49, res, &res_len) != LT_OK) {
        ensure_session("C06");
    }
    cmd[0] = 0x71;
    if (l3_raw("C06", "eddsa cmd_size=15", cmd, 15, res, &res_len) != LT_OK) {
        ensure_session("C06");
    }

    for (i = 29; i <= 31; i++) {
        (void)lt_ecc_key_erase(&g_h, (lt_ecc_slot_t)i);
    }
}

static void c_rmem(void)
{
    static uint8_t data[480], back[480];
    static uint8_t cmd[490];
    static uint8_t res[490];
    uint16_t res_len;
    uint16_t rlen;
    lt_ret_t ret;
    int      i;
    const uint16_t S = 511;

    for (i = 0; i < (int)sizeof(data); i++) {
        data[i] = (uint8_t)(0xa5 ^ i);
    }
    for (i = 509; i <= 511; i++) {
        (void)lt_r_mem_data_erase(&g_h, (uint16_t)i);
    }
    ret = lt_r_mem_data_read(&g_h, S, back, sizeof(back), &rlen);
    printf("T C07 read empty -> %s len=%u\n", rs(ret), rlen);
    cmd[0] = 0x41; cmd[1] = 0xff; cmd[2] = 0x01;
    l3_raw("C07", "read empty raw", cmd, 3, res, &res_len);
    ret = lt_r_mem_data_erase(&g_h, S);
    printf("T C07 erase empty -> %s\n", rs(ret));
    ret = lt_r_mem_data_write(&g_h, S, data, 1);
    printf("T C07 write 1 -> %s\n", rs(ret));
    ret = lt_r_mem_data_read(&g_h, S, back, sizeof(back), &rlen);
    printf("T C07 read 1 -> %s len=%u match=%d\n", rs(ret), rlen,
           memcmp(data, back, 1) == 0);
    l3_raw("C07", "read 1 raw", cmd, 3, res, &res_len);
    ret = lt_r_mem_data_write(&g_h, S, data, 1);
    printf("T C07 write occupied -> %s\n", rs(ret));
    ret = lt_r_mem_data_erase(&g_h, S);
    printf("T C07 erase -> %s\n", rs(ret));
    ret = lt_r_mem_data_read(&g_h, S, back, sizeof(back), &rlen);
    printf("T C07 read after erase -> %s len=%u\n", rs(ret), rlen);

    ret = lt_r_mem_data_write(&g_h, S, data, 444);
    printf("T C07 write 444 -> %s\n", rs(ret));
    ret = lt_r_mem_data_read(&g_h, S, back, sizeof(back), &rlen);
    printf("T C07 read 444 -> %s len=%u match=%d\n", rs(ret), rlen,
           memcmp(data, back, 444) == 0);
    (void)lt_r_mem_data_erase(&g_h, S);

    cmd[0] = 0x40; cmd[1] = 0xff; cmd[2] = 0x01; cmd[3] = 0;
    memcpy(cmd + 4, data, 476);
    l3_raw("C07", "write raw 445", cmd, 4 + 445, res, &res_len);
    (void)lt_r_mem_data_erase(&g_h, S);
    l3_raw("C07", "write raw 475", cmd, 4 + 475, res, &res_len);
    cmd[0] = 0x41;
    l3_raw("C07", "read after raw 475", cmd, 3, res, &res_len);
    (void)lt_r_mem_data_erase(&g_h, S);
    cmd[0] = 0x40;
    if (l3_raw("C07", "write raw 476", cmd, 4 + 476, res, &res_len) != LT_OK) {
        ensure_session("C07");
    }
    (void)lt_r_mem_data_erase(&g_h, S);
    if (l3_raw("C07", "write raw 0", cmd, 4, res, &res_len) != LT_OK) {
        ensure_session("C07");
    }
    (void)lt_r_mem_data_erase(&g_h, S);

    cmd[0] = 0x41; cmd[1] = 0x00; cmd[2] = 0x02;
    l3_raw("C07", "read slot=512", cmd, 3, res, &res_len);
    cmd[0] = 0x42;
    l3_raw("C07", "erase slot=512", cmd, 3, res, &res_len);
    cmd[0] = 0x40; cmd[3] = 0; cmd[4] = 0x55;
    l3_raw("C07", "write slot=512", cmd, 5, res, &res_len);
    cmd[0] = 0x41; cmd[1] = 0xff; cmd[2] = 0x01;
    if (l3_raw("C07", "read cmd_size=4", cmd, 4, res, &res_len) != LT_OK) {
        ensure_session("C07");
    }

    /* Slot independence */
    ret = lt_r_mem_data_write(&g_h, 509, data, 10);
    printf("T C07 write 509 -> %s\n", rs(ret));
    ret = lt_r_mem_data_read(&g_h, 510, back, sizeof(back), &rlen);
    printf("T C07 read 510 -> %s len=%u\n", rs(ret), rlen);
    for (i = 509; i <= 511; i++) {
        (void)lt_r_mem_data_erase(&g_h, (uint16_t)i);
    }
}

static void c_mcounter(void)
{
    uint8_t  cmd[16];
    uint8_t  res[16];
    uint16_t res_len;
    uint32_t v;
    lt_ret_t ret;
    int      i;
    const enum lt_mcounter_index_t M = TR01_MCOUNTER_INDEX_15;

    ret = lt_mcounter_init(&g_h, M, 3);
    printf("T C08 init 3 -> %s\n", rs(ret));
    for (i = 0; i < 5; i++) {
        v = 0xdeadbeef;
        ret = lt_mcounter_get(&g_h, M, &v);
        printf("T C08 get -> %s v=%" PRIu32 "\n", rs(ret), v);
        ret = lt_mcounter_update(&g_h, M);
        printf("T C08 update -> %s\n", rs(ret));
    }
    ret = lt_mcounter_init(&g_h, M, 0);
    printf("T C08 init 0 -> %s\n", rs(ret));
    ret = lt_mcounter_get(&g_h, M, &v);
    printf("T C08 get -> %s v=%" PRIu32 "\n", rs(ret), v);
    ret = lt_mcounter_update(&g_h, M);
    printf("T C08 update at 0 -> %s\n", rs(ret));
    ret = lt_mcounter_init(&g_h, M, 0xfffffffeu);
    printf("T C08 init fffffffe -> %s\n", rs(ret));
    ret = lt_mcounter_get(&g_h, M, &v);
    printf("T C08 get -> %s v=%08" PRIx32 "\n", rs(ret), v);
    ret = lt_mcounter_update(&g_h, M);
    printf("T C08 update -> %s\n", rs(ret));
    ret = lt_mcounter_get(&g_h, M, &v);
    printf("T C08 get -> %s v=%08" PRIx32 "\n", rs(ret), v);

    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 15; cmd[4] = 0xff; cmd[5] = 0xff; cmd[6] = 0xff;
    cmd[7] = 0xff;
    l3_raw("C08", "init ffffffff raw", cmd, 8, res, &res_len);
    cmd[0] = 0x82;
    l3_raw("C08", "get after ffffffff raw", cmd, 3, res, &res_len);
    cmd[0] = 0x81;
    l3_raw("C08", "update after ffffffff raw", cmd, 3, res, &res_len);
    cmd[0] = 0x82; cmd[1] = 16;
    l3_raw("C08", "get index=16", cmd, 3, res, &res_len);
    cmd[0] = 0x81;
    l3_raw("C08", "update index=16", cmd, 3, res, &res_len);
    cmd[0] = 0x80; cmd[4] = 1; cmd[5] = 0; cmd[6] = 0; cmd[7] = 0;
    l3_raw("C08", "init index=16", cmd, 8, res, &res_len);
    cmd[0] = 0x82; cmd[1] = 15;
    l3_raw("C08", "get index=15 raw", cmd, 3, res, &res_len);
    if (res_len == 8) {
        hexline("I C08 get raw=", res, 8);
    }

    ret = lt_mcounter_init(&g_h, M, 10);
    printf("T C08 re-init 10 -> %s\n", rs(ret));
    ret = lt_mcounter_get(&g_h, M, &v);
    printf("T C08 get -> %s v=%" PRIu32 "\n", rs(ret), v);
}

static void c_macandd(void)
{
    uint8_t  a[32], b[32], c[32];
    uint8_t  o1[32], o2[32], o3[32], o4[32];
    uint8_t  cmd[40];
    uint8_t  res[40];
    uint16_t res_len;
    lt_ret_t ret;
    const lt_mac_and_destroy_slot_t S = TR01_MAC_AND_DESTROY_SLOT_127;
    const lt_mac_and_destroy_slot_t S2 = TR01_MAC_AND_DESTROY_SLOT_126;

    memset(a, 0xa1, sizeof(a));
    memset(b, 0xb2, sizeof(b));
    memset(c, 0xc3, sizeof(c));

    /* Slot state persists across runs: start from a known one */
    (void)lt_mac_and_destroy(&g_h, S, c, o4);

    ret = lt_mac_and_destroy(&g_h, S, a, o1);
    printf("T C09 m&d A -> %s\n", rs(ret));
    ret = lt_mac_and_destroy(&g_h, S, a, o2);
    printf("T C09 m&d A -> %s\n", rs(ret));
    ret = lt_mac_and_destroy(&g_h, S, a, o3);
    printf("T C09 m&d A -> %s\n", rs(ret));
    printf("T C09 AA==AAA %d, A!=AA %d\n", memcmp(o2, o3, 32) == 0,
           memcmp(o1, o2, 32) != 0);

    (void)lt_mac_and_destroy(&g_h, S, a, o1);
    ret = lt_mac_and_destroy(&g_h, S, b, o1);
    (void)lt_mac_and_destroy(&g_h, S, c, o2);
    (void)lt_mac_and_destroy(&g_h, S, a, o2);
    ret = lt_mac_and_destroy(&g_h, S, b, o2);
    printf("T C09 out(A,B) history independent=%d\n", memcmp(o1, o2, 32) == 0);

    (void)lt_mac_and_destroy(&g_h, S2, a, o3);
    ret = lt_mac_and_destroy(&g_h, S2, b, o3);
    printf("T C09 slot dependent=%d\n", memcmp(o1, o3, 32) != 0);

    (void)lt_mac_and_destroy(&g_h, S, b, o4);
    ret = lt_mac_and_destroy(&g_h, S, a, o4);
    printf("T C09 order dependent=%d\n", memcmp(o1, o4, 32) != 0);

    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x90; cmd[1] = 128;
    l3_raw("C09", "m&d slot=128", cmd, 36, res, &res_len);
    cmd[1] = 127;
    if (l3_raw("C09", "m&d cmd_size=35", cmd, 35, res, &res_len) != LT_OK) {
        ensure_session("C09");
    }
    if (l3_raw("C09", "m&d cmd_size=4", cmd, 4, res, &res_len) != LT_OK) {
        ensure_session("C09");
    }
}

/* FW 2.x: a SPECT command (ECC, MAC_And_Destroy) rejected for its size
 * spoils the next command that is not a SPECT command, in later sessions
 * too, until a reboot. */
static uint8_t g_c10_res[TR01_L3_RES_CIPHERTEXT_MAX_SIZE];

static void c10_ping(const char* desc)
{
    static const uint8_t ping[] = {0x01, 0x11, 0x22, 0x33, 0x44};
    uint16_t res_len = 0;

    (void)l3_raw("C10", desc, ping, sizeof(ping), g_c10_res, &res_len);
    printf("T C10 %s echoed=%d\n", desc,
           res_len == sizeof(ping) &&
               memcmp(g_c10_res + 1, ping + 1, 4) == 0);
}

static void c10_reboot(void)
{
    lt_ret_t ret = lt_reboot(&g_h, TR01_REBOOT);
    printf("T C10 reboot -> %s\n", rs(ret));
    ret = start_session();
    printf("T C10 session -> %s\n", rs(ret));
}

/* Send a command of the wrong size; reopen the session it closes */
static void c10_bad(const char* desc, uint8_t id, uint8_t a, uint16_t len)
{
    uint8_t  cmd[64];
    uint16_t res_len;

    memset(cmd, 0, sizeof(cmd));
    cmd[0] = id;
    cmd[1] = a;
    if (l3_raw("C10", desc, cmd, len, g_c10_res, &res_len) != LT_OK) {
        ensure_session("C10");
    }
}

static void c_spect_size_error(void)
{
    static const struct {
        const char* desc;
        uint8_t     id;
        uint8_t     a;
        uint16_t    len;
    } bad[] = {
        {"m&d cmd_size=4", 0x90, 127, 4},
        {"ecc_gen cmd_size=5", 0x60, 31, 5},
        {"ecc_read cmd_size=4", 0x62, 31, 4},
        {"ecdsa cmd_size=47", 0x70, 31, 47},
        {"eddsa cmd_size=15", 0x71, 31, 15},
        {"random cmd_size=3", 0x50, 4, 3},
        {"rmem_read cmd_size=4", 0x41, 0xff, 4},
        {"mcounter_get cmd_size=4", 0x82, 15, 4},
    };
    uint8_t  cmd[16];
    uint16_t res_len;
    lt_ret_t ret;
    int      i;

    c10_reboot();
    for (i = 0; i < (int)(sizeof(bad) / sizeof(bad[0])); i++) {
        c10_bad(bad[i].desc, bad[i].id, bad[i].a, bad[i].len);
        c10_ping("ping #1");
        c10_ping("ping #2");
    }

    /* The spoiled command is not executed */
    c10_bad("m&d cmd_size=4", 0x90, 127, 4);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x40; cmd[1] = 0xff; cmd[2] = 0x01; cmd[4] = 0x5a;
    (void)l3_raw("C10", "rmem write slot=511", cmd, 5, g_c10_res, &res_len);
    cmd[0] = 0x41;
    (void)l3_raw("C10", "rmem read slot=511", cmd, 3, g_c10_res, &res_len);

    /* A SPECT command runs and clears it; so does an unknown command */
    c10_bad("m&d cmd_size=4", 0x90, 127, 4);
    cmd[0] = 0x63; cmd[1] = 31; cmd[2] = 0;
    (void)l3_raw("C10", "ecc_erase slot=31", cmd, 3, g_c10_res, &res_len);
    c10_ping("ping after ecc_erase");
    c10_bad("m&d cmd_size=4", 0x90, 127, 4);
    cmd[0] = 0xf0;
    (void)l3_raw("C10", "unknown cmd 0xf0", cmd, 1, g_c10_res, &res_len);
    c10_ping("ping after unknown cmd");

    /* It outlives a session that sends no command; a reboot clears it */
    c10_bad("m&d cmd_size=4", 0x90, 127, 4);
    ret = lt_session_abort(&g_h);
    printf("T C10 session abort -> %s\n", rs(ret));
    ret = start_session();
    printf("T C10 session -> %s\n", rs(ret));
    c10_ping("ping after new session");
    c10_bad("m&d cmd_size=4", 0x90, 127, 4);
    c10_reboot();
    c10_ping("ping after reboot");

    (void)lt_r_mem_data_erase(&g_h, 511);
}

static void section_c(void)
{
    ensure_session("C00");
    c_ping();
    ensure_session("C01");
    c_unknown();
    ensure_session("C02");
    c_random();
    ensure_session("C03");
    c_pairing();
    ensure_session("C04");
    c_config();
    ensure_session("C05");
    c_ecc();
    ensure_session("C06");
    c_rmem();
    ensure_session("C07");
    c_mcounter();
    ensure_session("C08");
    c_macandd();
    if (g_fw_major >= 2) {
        c_spect_size_error();
    }
}

/* ------------------------------------------------------------------------ */
/* Section D: reboot and maintenance mode */

static void section_d(void)
{
    static uint8_t certs[4][TR01_L2_GET_INFO_REQ_CERT_SIZE_SINGLE];
    struct lt_cert_store_t store;
    lt_tr01_mode_t mode;
    uint8_t  ping_out[8] = "ping-me", ping_in[8];
    uint8_t  d[4];
    uint8_t  rsp[256];
    uint8_t  rlen;
    uint8_t  hdr[64];
    lt_ret_t ret;
    int      i;

    ensure_session("D00");
    ret = lt_reboot(&g_h, TR01_REBOOT);
    printf("T D01 reboot -> %s\n", rs(ret));
    ret = lt_get_tr01_mode(&g_h, &mode);
    printf("T D01 mode -> %s mode=%d\n", rs(ret), (int)mode);
    g_h.l3.session_status = LT_SECURE_SESSION_ON;
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T D01 ping with stale session -> %s\n", rs(ret));
    g_h.l3.session_status = LT_SECURE_SESSION_OFF;

    ret = lt_reboot(&g_h, TR01_MAINTENANCE_REBOOT);
    printf("T D02 maintenance reboot -> %s\n", rs(ret));
    ret = lt_get_tr01_mode(&g_h, &mode);
    printf("T D02 mode -> %s mode=%d\n", rs(ret), (int)mode);
    trace_start();
    d[0] = 0x02; d[1] = 0;
    l2_raw("D02", "get_info riscv_fw (bootloader)", 0x01, d, 2, 0, rsp, &rlen);
    trace_stop("I D02 trace:");
    hexline("I D02 bootloader=", rsp, rlen);
    d[0] = 0x04;
    l2_raw("D02", "get_info spect_fw", 0x01, d, 2, 0, rsp, &rlen);
    hexline("I D02 spect=", rsp, rlen);
    d[0] = 0x01;
    l2_raw("D02", "get_info chip_id", 0x01, d, 2, 0, rsp, &rlen);
    d[0] = 0x00;
    l2_raw("D02", "get_info cert block 0", 0x01, d, 2, 0, rsp, &rlen);
    {
        static const uint8_t banks[] = {0x01, 0x02, 0x11, 0x12, 0x03};
        for (i = 0; i < (int)sizeof(banks); i++) {
            char desc[40];
            d[0] = 0xb0; d[1] = banks[i];
            snprintf(desc, sizeof(desc), "get_info fw_bank %02x", banks[i]);
            l2_raw("D02", desc, 0x01, d, 2, 0, hdr, &rlen);
            if (rlen > 0) {
                hexline("I D02 bank hdr=", hdr, rlen > 32 ? 32 : rlen);
            }
        }
    }
    memset(&store, 0, sizeof(store));
    for (i = 0; i < 4; i++) {
        store.certs[i]   = certs[i];
        store.buf_len[i] = sizeof(certs[i]);
    }
    ret = lt_get_info_cert_store(&g_h, &store);
    printf("T D02 cert_store -> %s\n", rs(ret));
    ret = start_session();
    printf("T D02 session in maintenance -> %s\n", rs(ret));
    memset(rsp, 0x11, 64);
    rsp[0] = 0x01; rsp[1] = 0x00;
    l2_raw("D02", "encrypted_cmd", 0x04, rsp, 19, 0, NULL, NULL);
    d[0] = 0x05;
    l2_raw("D02", "sleep", 0x20, d, 1, 0, NULL, NULL);
    l2_raw("D02", "get_log", 0xa2, d, 0, 0, NULL, NULL);

    ret = lt_reboot(&g_h, TR01_REBOOT);
    printf("T D03 reboot -> %s\n", rs(ret));
    ret = lt_get_tr01_mode(&g_h, &mode);
    printf("T D03 mode -> %s mode=%d\n", rs(ret), (int)mode);
    ret = start_session();
    printf("T D03 session -> %s\n", rs(ret));
    ret = lt_ping(&g_h, ping_out, ping_in, sizeof(ping_out));
    printf("T D03 ping -> %s\n", rs(ret));
    (void)lt_session_abort(&g_h);
}

#ifdef CONF_ALARM_TEST
/* Requests observed to put the FW 0.1.2 engineering sample into ALARM mode
 * (FW 2.2.0 answers HSK_ERR, checked in A14).
 * Only built with -DCONF_ALARM_TEST; recovering needs a full power cycle. */
static void section_z(void)
{
    uint8_t rsp[64];
    memset(rsp, 0x42, sizeof(rsp));
    rsp[32] = CONF_ALARM_TEST;
    l2_raw("Z01", "handshake pkey=N", 0x02, rsp, 33, 0, NULL, NULL);
    l2_raw("Z01", "get_info after", 0x01, rsp, 2, 0, NULL, NULL);
}
#endif

/* ------------------------------------------------------------------------ */

int tr01_conf_run(void)
{
    lt_ret_t ret;

    memset(&g_h, 0, sizeof(g_h));
    plat_setup_handle(&g_h);
    ret = lt_init(&g_h);
    printf("T 000 lt_init -> %s\n", rs(ret));
    if (ret != LT_OK) {
        return 1;
    }
#ifdef CONF_ALARM_TEST
    section_z();
#else
    section_a();
    if (!g_alarm) section_b();
    if (!g_alarm) section_c();
    if (!g_alarm) section_d();
    if (g_alarm) printf("ABORT: chip entered ALARM mode\n");
#endif
    lt_deinit(&g_h);
    printf("CONFORMANCE DONE\n");
    (void)g_fail_local;
    return 0;
}
