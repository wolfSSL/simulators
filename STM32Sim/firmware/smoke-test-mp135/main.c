/* main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Smoke-test firmware for the STM32MP135 chip target. Brings up the
 * MMU (1 MiB section identity map), then drives UART4, RNG1, CRYP1,
 * and HASH1 directly through MMIO. Sets test_complete/test_result
 * the same way the H7/U5 smoke tests do so the simulator's exit
 * polling and the cargo-test smoke harness can both observe the
 * outcome.
 */

#include <stdint.h>

void mmu_enable(void);

#define UART4_BASE   0x40010000u
#define UART4_CR1    (*(volatile uint32_t *)(UART4_BASE + 0x00))
#define UART4_BRR    (*(volatile uint32_t *)(UART4_BASE + 0x0C))
#define UART4_ISR    (*(volatile uint32_t *)(UART4_BASE + 0x1C))
#define UART4_TDR    (*(volatile uint32_t *)(UART4_BASE + 0x28))

#define USART_CR1_UE  (1u << 0)
#define USART_CR1_TE  (1u << 3)
#define USART_ISR_TXE (1u << 7)

#define RNG1_BASE 0x54004000u
#define RNG_CR    (*(volatile uint32_t *)(RNG1_BASE + 0x00))
#define RNG_SR    (*(volatile uint32_t *)(RNG1_BASE + 0x04))
#define RNG_DR    (*(volatile uint32_t *)(RNG1_BASE + 0x08))
#define RNG_CR_RNGEN (1u << 2)
#define RNG_SR_DRDY  (1u << 0)

#define CRYP1_BASE 0x54002000u
#define CRYP_CR    (*(volatile uint32_t *)(CRYP1_BASE + 0x00))
#define CRYP_DIN   (*(volatile uint32_t *)(CRYP1_BASE + 0x08))
#define CRYP_DOUT  (*(volatile uint32_t *)(CRYP1_BASE + 0x0C))
#define CRYP_K2LR  (*(volatile uint32_t *)(CRYP1_BASE + 0x30))
#define CRYP_CR_CRYPEN (1u << 15)
#define CRYP_CR_ALGODIR (1u << 2)
#define CRYP_CR_ALGOMODE_AES_ECB (0b100u << 3)

#define HASH1_BASE 0x54003000u
#define HASH_CR    (*(volatile uint32_t *)(HASH1_BASE + 0x000))
#define HASH_DIN   (*(volatile uint32_t *)(HASH1_BASE + 0x004))
#define HASH_STR   (*(volatile uint32_t *)(HASH1_BASE + 0x008))
#define HASH_HR_EXT_BASE (HASH1_BASE + 0x310u)
#define HASH_CR_INIT    (1u << 2)
/* MP13 HASH ALGO is a 4-bit field at CR[20:17] (not the 2-bit
 * {7,18} layout the H7 uses). Encoding: 0=SHA-1, 1=MD5, 2=SHA-224,
 * 3=SHA-256, 4..7=SHA3-{224,256,384,512}, 8/9=SHAKE-{128,256}. */
#define HASH_CR_ALGO_SHA256  (3u << 17)
#define HASH_CR_ALGO_SHA3_256 (5u << 17)
#define HASH_STR_DCAL   (1u << 8)

volatile int test_result   __attribute__((section(".data"))) = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

static void uart_putc(char c)
{
    while (!(UART4_ISR & USART_ISR_TXE)) {
    }
    UART4_TDR = (uint32_t)c;
}

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s++);
    }
}

static void uart_put_hex32(uint32_t v)
{
    static const char hex[] = "0123456789abcdef";
    char out[11];
    out[0] = '0'; out[1] = 'x';
    for (int i = 0; i < 8; i++) {
        out[2 + i] = hex[(v >> ((7 - i) * 4)) & 0xF];
    }
    out[10] = 0;
    uart_puts(out);
}

int main(void)
{
    mmu_enable();

    UART4_BRR = 64000000u / 115200u;
    UART4_CR1 = USART_CR1_UE | USART_CR1_TE;

    uart_puts("\n=== STM32Sim MP135 smoke test ===\n");

    RNG_CR = RNG_CR_RNGEN;
    for (int i = 0; i < 4; i++) {
        while (!(RNG_SR & RNG_SR_DRDY)) {
        }
        uint32_t v = RNG_DR;
        uart_puts("rng[");
        uart_putc('0' + (char)i);
        uart_puts("] = ");
        uart_put_hex32(v);
        uart_puts("\n");
    }

    /* AES-128 ECB round-trip through CRYP1. Same FIPS-197 Appendix B
     * vector the H7 smoke test uses, so the simulator's shared engine
     * is exercised identically. */
    int aes_ok = 1;
    {
        volatile uint32_t *key = &CRYP_K2LR;
        key[0] = 0x2b7e1516u;
        key[1] = 0x28aed2a6u;
        key[2] = 0xabf71588u;
        key[3] = 0x09cf4f3cu;

        CRYP_CR = CRYP_CR_ALGOMODE_AES_ECB | CRYP_CR_CRYPEN;
        CRYP_DIN = 0x3243f6a8u;
        CRYP_DIN = 0x885a308du;
        CRYP_DIN = 0x313198a2u;
        CRYP_DIN = 0xe0370734u;
        uint32_t c0 = CRYP_DOUT;
        uint32_t c1 = CRYP_DOUT;
        uint32_t c2 = CRYP_DOUT;
        uint32_t c3 = CRYP_DOUT;
        CRYP_CR = 0;

        if (c0 != 0x3925841du || c1 != 0x02dc09fbu ||
            c2 != 0xdc118597u || c3 != 0x196a0b32u) {
            aes_ok = 0;
            uart_puts("AES-128 ECB encrypt mismatch\n");
        }

        CRYP_CR = CRYP_CR_ALGOMODE_AES_ECB | CRYP_CR_ALGODIR | CRYP_CR_CRYPEN;
        CRYP_DIN = c0; CRYP_DIN = c1; CRYP_DIN = c2; CRYP_DIN = c3;
        uint32_t p0 = CRYP_DOUT, p1 = CRYP_DOUT, p2 = CRYP_DOUT, p3 = CRYP_DOUT;
        CRYP_CR = 0;

        if (p0 != 0x3243f6a8u || p1 != 0x885a308du ||
            p2 != 0x313198a2u || p3 != 0xe0370734u) {
            aes_ok = 0;
            uart_puts("AES-128 ECB decrypt mismatch\n");
        }

        if (aes_ok) {
            uart_puts("AES-128 ECB round-trip OK\n");
        }
    }

    /* SHA-256 of "abc" through HASH1. */
    int hash_ok = 1;
    {
        HASH_CR = HASH_CR_ALGO_SHA256 | HASH_CR_INIT;
        HASH_DIN = 0x61626300u;
        HASH_STR = HASH_STR_DCAL | 24u;
        volatile uint32_t *hr = (volatile uint32_t *)HASH_HR_EXT_BASE;
        const uint32_t expected[8] = {
            0xba7816bfu, 0x8f01cfeau, 0x414140deu, 0x5dae2223u,
            0xb00361a3u, 0x96177a9cu, 0xb410ff61u, 0xf20015adu,
        };
        for (int i = 0; i < 8; i++) {
            if (hr[i] != expected[i]) {
                hash_ok = 0;
                uart_puts("SHA-256 mismatch\n");
                break;
            }
        }
        if (hash_ok) {
            uart_puts("SHA-256 \"abc\" OK\n");
        }
    }

    /* SHA3-256 of "abc" through HASH1. Same KAT shape as SHA-256
     * but with ALGO=5 instead of 3, exercising the MP13-only SHA3
     * code path on the chip. */
    int sha3_ok = 1;
    {
        HASH_CR = HASH_CR_ALGO_SHA3_256 | HASH_CR_INIT;
        HASH_DIN = 0x61626300u;
        HASH_STR = HASH_STR_DCAL | 24u;
        volatile uint32_t *hr = (volatile uint32_t *)HASH_HR_EXT_BASE;
        const uint32_t expected[8] = {
            0x3a985da7u, 0x4fe225b2u, 0x045c172du, 0x6bd390bdu,
            0x855f086eu, 0x3e9d525bu, 0x46bfe245u, 0x11431532u,
        };
        for (int i = 0; i < 8; i++) {
            if (hr[i] != expected[i]) {
                sha3_ok = 0;
                uart_puts("SHA3-256 mismatch\n");
                break;
            }
        }
        if (sha3_ok) {
            uart_puts("SHA3-256 \"abc\" OK\n");
        }
    }
    hash_ok = hash_ok && sha3_ok;

    if (!aes_ok || !hash_ok) {
        test_result = 1;
        test_complete = 1;
        for (;;) {
            __asm__ volatile ("");
        }
    }

    uart_puts("=== smoke test passed ===\n");

    test_result = 0;
    test_complete = 1;

    /* Spin until the simulator notices test_complete on its next
     * slice. Plain branch-to-self - no wfe/wfi, those are decoded
     * as invalid instructions by Unicorn's Cortex-A7 model. */
    for (;;) {
        __asm__ volatile ("");
    }
}
