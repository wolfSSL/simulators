/* main.c - PIC32MZ EF smoke test
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Bare-metal smoke firmware: drives the simulated Crypto Engine
 * through an AES-128 ECB round-trip plus SHA-256("abc"), drains a few
 * RNG words, and reports pass/fail via the test_complete/test_result
 * symbols the simulator runner polls. This exercises every register
 * the wolfSSL PIC32 port pokes, end-to-end through the BD+SA layout.
 */

#include <stdint.h>
#include <stddef.h>
#include "pic32mz_stubs.h"

/* Self-contained mem* implementations - keeps the smoke firmware
 * link-independent of newlib so it can be built from the bare cargo
 * test workflow without the Docker image's newlib install. */
static void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}
static void *memset(void *p, int c, size_t n)
{
    unsigned char *q = (unsigned char *)p;
    while (n--) *q++ = (unsigned char)c;
    return p;
}
static int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    while (n--) {
        if (*x != *y) return (int)*x - (int)*y;
        x++; y++;
    }
    return 0;
}

#define PIC32_ALGO_SHA256    0x20u
#define PIC32_ALGO_AES       0x04u
#define PIC32_CRYPTOALGO_RECB 0x08u
#define PIC32_KEYSIZE_128    0x00u

/* SA / BD bit-field layouts mirror wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h.
 * Defined here so the smoke firmware does not depend on a wolfSSL
 * checkout being present. */
typedef struct __attribute__((aligned(8))) {
    uint32_t SA_CTRL;
    uint32_t SA_AUTHKEY[8];
    uint32_t SA_ENCKEY[8];
    uint32_t SA_AUTHIV[8];
    uint32_t SA_ENCIV[4];
} sa_t;

typedef struct __attribute__((aligned(8))) {
    uint32_t BD_CTRL;
    uint32_t SA_ADDR;
    uint32_t SRCADDR;
    uint32_t DSTADDR;
    uint32_t NXTPTR;
    uint32_t UPDPTR;
    uint32_t MSGLEN;
    uint32_t ENCOFF;
} bd_t;

#define BD_CTRL(buflen)                                                 \
    (((buflen) & 0xFFFF)                                                \
     | (1u << 17)  /* PKT_INT_EN */                                     \
     | (1u << 18)  /* LIFM */                                           \
     | (1u << 19)  /* LAST_BD */                                        \
     | (1u << 22)  /* SA_FETCH_EN */                                    \
     | (1u << 31)) /* DESC_EN */

#define SA_CTRL_AES(keysize, encrypt)                                   \
    ((PIC32_CRYPTOALGO_RECB & 0xF)                                      \
     | (((keysize) & 0x3) << 7)                                         \
     | (((encrypt) & 0x1) << 9)                                         \
     | ((PIC32_ALGO_AES & 0x7F) << 10)                                  \
     | (1u << 21)  /* FB - first block */                               \
     | (1u << 23)) /* LNC - load new keys */

#define SA_CTRL_SHA256                                                  \
    (((PIC32_ALGO_SHA256 & 0x7F) << 10)                                 \
     | (1u << 21)  /* FB */                                             \
     | (1u << 22)) /* LOADIV */

/* Buffers placed in BSS (KSEG1 SRAM). */
static sa_t  g_sa;
static bd_t  g_bd;
static uint8_t g_in[64]  __attribute__((aligned(4)));
static uint8_t g_out[64] __attribute__((aligned(4)));

volatile int test_result   __attribute__((section(".data"))) = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

static void uart_putc(char c)
{
    U2TXREG = (uint32_t)(unsigned char)c;
}
static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}
static void uart_put_hex32(uint32_t v)
{
    static const char hex[] = "0123456789abcdef";
    uart_putc('0'); uart_putc('x');
    for (int i = 0; i < 8; i++) {
        uart_putc(hex[(v >> ((7 - i) * 4)) & 0xF]);
    }
}

static int ce_run_blocking(void)
{
    CECON = (1u << 6); /* SWRST */
    while (CECON);
    CEINTSRC = 0xF;
    CEBDPADDR = (uint32_t)KVA_TO_PA(&g_bd);
    CEINTEN = 0x07;
    /* 0xA5: input swap + BD fetch + start + output swap (EF only). */
    CECON = 0xa5u;
    int timeout = 0x100000;
    while (!CEINTSRCbits.PKTIF && --timeout > 0) { }
    if (timeout <= 0) return -1;
    if (CESTATbits.ERROP) return -2;
    CEINTSRC = 0xF;
    return 0;
}

static int test_aes128_ecb(void)
{
    /* FIPS-197 vector. */
    const uint32_t key_be[4] = {
        0x2b7e1516u, 0x28aed2a6u, 0xabf71588u, 0x09cf4f3cu
    };
    const uint8_t  pt[16] = {
        0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a
    };
    const uint8_t  ct_expected[16] = {
        0x3a,0xd7,0x7b,0xb4, 0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3, 0x24,0x66,0xef,0x97
    };

    memset(&g_sa, 0, sizeof(g_sa));
    g_sa.SA_CTRL = SA_CTRL_AES(PIC32_KEYSIZE_128, 1 /* encrypt */);
    /* Right-justify key in SA_ENCKEY (last 4 of 8 words). The driver
     * uses ByteReverseWords; on LE that's equivalent to storing the
     * big-endian view of each word straight into the u32. */
    for (int i = 0; i < 4; i++) g_sa.SA_ENCKEY[4 + i] = key_be[i];

    memset(&g_bd, 0, sizeof(g_bd));
    g_bd.BD_CTRL = BD_CTRL(16);
    g_bd.SA_ADDR = (uint32_t)KVA_TO_PA(&g_sa);
    memcpy(g_in, pt, 16);
    g_bd.SRCADDR = (uint32_t)KVA_TO_PA(g_in);
    g_bd.DSTADDR = (uint32_t)KVA_TO_PA(g_out);
    g_bd.NXTPTR  = (uint32_t)KVA_TO_PA(&g_bd);
    g_bd.MSGLEN  = 16;

    if (ce_run_blocking() != 0) {
        uart_puts("AES ECB engine error\n");
        return -1;
    }
    if (memcmp(g_out, ct_expected, 16) != 0) {
        uart_puts("AES-128 ECB ciphertext mismatch\n");
        return -1;
    }

    /* Decrypt round-trip. */
    g_sa.SA_CTRL = SA_CTRL_AES(PIC32_KEYSIZE_128, 0 /* decrypt */);
    g_bd.BD_CTRL = BD_CTRL(16);
    memcpy(g_in, ct_expected, 16);
    if (ce_run_blocking() != 0) {
        uart_puts("AES ECB decrypt engine error\n");
        return -1;
    }
    if (memcmp(g_out, pt, 16) != 0) {
        uart_puts("AES-128 ECB decrypt mismatch\n");
        return -1;
    }

    uart_puts("AES-128 ECB round-trip OK\n");
    return 0;
}

static int test_sha256_abc(void)
{
    const uint8_t expected[32] = {
        0xba,0x78,0x16,0xbf, 0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde, 0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3, 0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61, 0xf2,0x00,0x15,0xad
    };
    /* SHA-256 FIPS-180-4 H0..H7. */
    const uint32_t h0[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };

    memset(&g_sa, 0, sizeof(g_sa));
    g_sa.SA_CTRL = SA_CTRL_SHA256;
    for (int i = 0; i < 8; i++) g_sa.SA_AUTHIV[i] = h0[i];

    memset(&g_bd, 0, sizeof(g_bd));
    g_bd.BD_CTRL = BD_CTRL(4); /* "abc" padded to 4 bytes */
    g_bd.SA_ADDR = (uint32_t)KVA_TO_PA(&g_sa);
    memset(g_in, 0, sizeof(g_in));
    g_in[0] = 'a'; g_in[1] = 'b'; g_in[2] = 'c';
    g_bd.SRCADDR = (uint32_t)KVA_TO_PA(g_in);
    g_bd.UPDPTR  = (uint32_t)KVA_TO_PA(g_out);
    g_bd.NXTPTR  = (uint32_t)KVA_TO_PA(&g_bd);
    g_bd.MSGLEN  = 3;

    if (ce_run_blocking() != 0) {
        uart_puts("SHA-256 engine error\n");
        return -1;
    }
    if (memcmp(g_out, expected, 32) != 0) {
        uart_puts("SHA-256(\"abc\") digest mismatch\n");
        return -1;
    }
    uart_puts("SHA-256 \"abc\" OK\n");
    return 0;
}

static int test_rng_words(void)
{
    /* EF path: TRNG seeds, then PRNG runs. wolfSSL random.c sequence. */
    RNGNUMGEN1 = _CP0_GET_COUNT();
    RNGPOLY1   = _CP0_GET_COUNT();
    RNGPOLY2   = 0;
    RNGCONbits.TRNGMODE = 1;
    RNGCONbits.TRNGEN   = 1;
    int spins = 0;
    while (RNGCNT < 64 && spins++ < 0x1000) { }
    if (RNGCNT < 64) {
        uart_puts("RNG TRNG never seeded\n");
        return -1;
    }
    RNGCONbits.LOAD = 1;
    while (RNGCONbits.LOAD == 1 && spins++ < 0x10000) { }
    RNGPOLY2 = RNGSEED2;
    RNGPOLY1 = RNGSEED1;
    RNGCONbits.PLEN = 0x40;
    RNGCONbits.PRNGEN = 1;

    uint32_t a = RNGNUMGEN1;
    uint32_t b = RNGNUMGEN1;
    if (a == 0 && b == 0) {
        uart_puts("RNG returned all zeros\n");
        return -1;
    }
    uart_puts("rng=");
    uart_put_hex32(a);
    uart_puts(",");
    uart_put_hex32(b);
    uart_puts("\n");
    return 0;
}

int main(void)
{
    /* Init UART2 (BRG value is don't-care for the simulator). */
    U2BRG  = 50;
    U2MODE = (1u << 15); /* ON */
    U2STA  = (1u << 10); /* UTXEN */

    uart_puts("\n=== PIC32MZ EF smoke test ===\n");

    int rc = 0;
    rc |= test_aes128_ecb();
    rc |= test_sha256_abc();
    rc |= test_rng_words();

    if (rc != 0) {
        uart_puts("=== smoke test FAILED ===\n");
        test_result = 1;
        test_complete = 1;
        for (;;) { __asm__ volatile ("nop"); }
    }

    uart_puts("=== smoke test passed ===\n");
    test_result = 0;
    test_complete = 1;
    for (;;) { __asm__ volatile ("nop"); }
    return 0;
}
