/* main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Smoke-test firmware for the wolfSSL STM32 simulator. Boots, prints a
 * banner over USART3, reads a few words from the RNG, then sets the
 * test_complete flag and spin-loops forever. This exercises the boot
 * path, ELF loader, MMIO bus, USART, RCC, and RNG peripherals.
 */

#include <stdint.h>

#define USART3_BASE   0x40004800u
#define USART3_CR1    (*(volatile uint32_t *)(USART3_BASE + 0x00))
#define USART3_BRR    (*(volatile uint32_t *)(USART3_BASE + 0x0C))
#define USART3_ISR    (*(volatile uint32_t *)(USART3_BASE + 0x1C))
#define USART3_TDR    (*(volatile uint32_t *)(USART3_BASE + 0x28))

#define USART_CR1_UE  (1u << 0)
#define USART_CR1_TE  (1u << 3)
#define USART_ISR_TXE (1u << 7)

#define RCC_BASE          0x58024400u
#define RCC_APB1LENR      (*(volatile uint32_t *)(RCC_BASE + 0xE8))
#define RCC_APB1LENR_USART3EN (1u << 18)

#define RNG_BASE  0x48021800u
#define RNG_CR    (*(volatile uint32_t *)(RNG_BASE + 0x00))
#define RNG_SR    (*(volatile uint32_t *)(RNG_BASE + 0x04))
#define RNG_DR    (*(volatile uint32_t *)(RNG_BASE + 0x08))
#define RNG_CR_RNGEN (1u << 2)
#define RNG_SR_DRDY  (1u << 0)

#define CRYP_BASE  0x48021000u
#define CRYP_CR    (*(volatile uint32_t *)(CRYP_BASE + 0x00))
#define CRYP_SR    (*(volatile uint32_t *)(CRYP_BASE + 0x04))
#define CRYP_DIN   (*(volatile uint32_t *)(CRYP_BASE + 0x08))
#define CRYP_DOUT  (*(volatile uint32_t *)(CRYP_BASE + 0x0C))
#define CRYP_K0LR  (*(volatile uint32_t *)(CRYP_BASE + 0x20))
#define CRYP_K2LR  (*(volatile uint32_t *)(CRYP_BASE + 0x30))

/* H7 CRYP_CR layout: bit 14 FFLUSH, bit 15 CRYPEN. */
#define CRYP_CR_CRYPEN (1u << 15)
#define CRYP_CR_ALGODIR (1u << 2)
#define CRYP_CR_ALGOMODE_AES_ECB (0b100u << 3)

#define HASH_BASE  0x48021400u
#define HASH_CR    (*(volatile uint32_t *)(HASH_BASE + 0x000))
#define HASH_DIN   (*(volatile uint32_t *)(HASH_BASE + 0x004))
#define HASH_STR   (*(volatile uint32_t *)(HASH_BASE + 0x008))
#define HASH_HR_EXT_BASE (HASH_BASE + 0x310u)
#define HASH_CR_INIT (1u << 2)  /* H7 HASH_CR.INIT is at bit 2 */
#define HASH_CR_ALGO_LO (1u << 7)
#define HASH_CR_ALGO_HI (1u << 18)
#define HASH_STR_DCAL (1u << 8)

volatile int test_result __attribute__((section(".data")))   = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

static void uart_putc(char c)
{
    while (!(USART3_ISR & USART_ISR_TXE)) {
    }
    USART3_TDR = (uint32_t)c;
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

void Reset_Handler(void)
{
    extern uint32_t __data_start__, __data_end__, __etext;
    extern uint32_t __bss_start__, __bss_end__;

    uint32_t *src = &__etext;
    for (uint32_t *dst = &__data_start__; dst < &__data_end__; ) {
        *dst++ = *src++;
    }
    for (uint32_t *dst = &__bss_start__; dst < &__bss_end__; dst++) {
        *dst = 0;
    }

    RCC_APB1LENR |= RCC_APB1LENR_USART3EN;
    USART3_BRR = 64000000u / 115200u;
    USART3_CR1 = USART_CR1_UE | USART_CR1_TE;

    uart_puts("\n=== STM32Sim smoke test ===\n");

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

    /* AES-128 ECB round-trip through the CRYP peripheral.
     * FIPS-197 Appendix B vectors:
     *   key = 2b7e151628aed2a6abf7158809cf4f3c
     *   pt  = 3243f6a8885a308d313198a2e0370734
     *   ct  = 3925841d02dc09fbdc118597196a0b32
     */
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

    /* SHA-256 of "abc" through the HASH peripheral.
     * Expected = ba7816bf 8f01cfea 414140de 5dae2223
     *            b00361a3 96177a9c b410ff61 f20015ad
     */
    int hash_ok = 1;
    {
        HASH_CR = HASH_CR_ALGO_HI | HASH_CR_ALGO_LO | HASH_CR_INIT;
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

    if (!aes_ok || !hash_ok) {
        test_result = 1;
        test_complete = 1;
        for (;;) { __asm__ volatile ("wfi"); }
    }
    (void)hash_ok;

    uart_puts("=== smoke test passed ===\n");

    test_result = 0;
    test_complete = 1;

    for (;;) {
        __asm__ volatile ("wfi");
    }
}

void Default_Handler(void)
{
    for (;;) { __asm__ volatile ("wfi"); }
}
