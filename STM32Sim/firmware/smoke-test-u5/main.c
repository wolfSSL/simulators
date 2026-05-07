/* main.c - U5 smoke-test firmware
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Drives the STM32U575 v2 CRYP and HASH peripherals through the same
 * code path as the H7 smoke test, exercising the U5-specific register
 * encodings. Validates that one ARM ELF + one simulator runs against
 * either chip target with only base-address and bit-layout deltas.
 */

#include <stdint.h>

#define USART1_BASE   0x40013800u
#define USART1_CR1    (*(volatile uint32_t *)(USART1_BASE + 0x00))
#define USART1_BRR    (*(volatile uint32_t *)(USART1_BASE + 0x0C))
#define USART1_ISR    (*(volatile uint32_t *)(USART1_BASE + 0x1C))
#define USART1_TDR    (*(volatile uint32_t *)(USART1_BASE + 0x28))
#define USART_CR1_UE  (1u << 0)
#define USART_CR1_TE  (1u << 3)
#define USART_ISR_TXE (1u << 7)

#define AES_BASE   0x420C0000u
#define AES_CR     (*(volatile uint32_t *)(AES_BASE + 0x00))
#define AES_DINR   (*(volatile uint32_t *)(AES_BASE + 0x08))
#define AES_DOUTR  (*(volatile uint32_t *)(AES_BASE + 0x0C))
#define AES_KEYR0  ((volatile uint32_t *)(AES_BASE + 0x10))
#define AES_CR_EN  (1u << 0)
/* CHMOD = 000 (ECB) at bits[7:5]; MODE = 00 at bits[4:3]; KEYSIZE=128 (bit 18=0) */

#define HASH_BASE  0x420C0400u
#define HASH_CR    (*(volatile uint32_t *)(HASH_BASE + 0x000))
#define HASH_DIN   (*(volatile uint32_t *)(HASH_BASE + 0x004))
#define HASH_STR   (*(volatile uint32_t *)(HASH_BASE + 0x008))
#define HASH_HR    ((volatile uint32_t *)(HASH_BASE + 0x310))
/* U5 HASH_CR layout: INIT bit 2, ALGO at bits {18, 17}. The U5 RM
 * places the 2-bit ALGO field at bits 17 and 18, not bit 7 and bit 18
 * as on H7. SHA-256 = ALGO 11 = bit 18 + bit 17. */
#define HASH_CR_INIT (1u << 2)
#define HASH_CR_ALGO_LO (1u << 17)
#define HASH_CR_ALGO_HI (1u << 18)
#define HASH_STR_DCAL (1u << 8)

volatile int test_result __attribute__((section(".data")))   = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

static void uart_putc(char c)
{
    while (!(USART1_ISR & USART_ISR_TXE)) {
    }
    USART1_TDR = (uint32_t)c;
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

void Reset_Handler(void)
{
    extern uint32_t __data_start__, __data_end__, __etext;
    extern uint32_t __bss_start__, __bss_end__;

    uint32_t *src = &__etext;
    for (uint32_t *dst = &__data_start__; dst < &__data_end__;) {
        *dst++ = *src++;
    }
    for (uint32_t *dst = &__bss_start__; dst < &__bss_end__; dst++) {
        *dst = 0;
    }

    USART1_BRR = 64000000u / 115200u;
    USART1_CR1 = USART_CR1_UE | USART_CR1_TE;

    uart_puts("\n=== STM32U575 smoke test ===\n");

    /* AES-128 ECB through the U5 v2 register layout.
     * KEYR3 is the high word, KEYR0 the low; CHMOD=000 (bits 7:5) gives ECB.
     */
    int aes_ok = 1;
    AES_KEYR0[0] = 0x09cf4f3cu;
    AES_KEYR0[1] = 0xabf71588u;
    AES_KEYR0[2] = 0x28aed2a6u;
    AES_KEYR0[3] = 0x2b7e1516u;

    AES_CR = AES_CR_EN; /* CHMOD=0 (ECB), MODE=0 (encrypt) */
    AES_DINR = 0x3243f6a8u;
    AES_DINR = 0x885a308du;
    AES_DINR = 0x313198a2u;
    AES_DINR = 0xe0370734u;
    uint32_t c0 = AES_DOUTR, c1 = AES_DOUTR, c2 = AES_DOUTR, c3 = AES_DOUTR;
    AES_CR = 0;

    if (c0 != 0x3925841du || c1 != 0x02dc09fbu ||
        c2 != 0xdc118597u || c3 != 0x196a0b32u) {
        aes_ok = 0;
        uart_puts("U5 AES-128 ECB mismatch\n");
    } else {
        uart_puts("U5 AES-128 ECB OK\n");
    }

    /* SHA-256 of "abc" through the U5 HASH_CR encoding
     * (ALGO bits {18, 17} = SHA-256). */
    int hash_ok = 1;
    HASH_CR = HASH_CR_ALGO_HI | HASH_CR_ALGO_LO | HASH_CR_INIT;
    HASH_DIN = 0x61626300u;
    HASH_STR = HASH_STR_DCAL | 24u;
    const uint32_t expected[8] = {
        0xba7816bfu, 0x8f01cfeau, 0x414140deu, 0x5dae2223u,
        0xb00361a3u, 0x96177a9cu, 0xb410ff61u, 0xf20015adu,
    };
    for (int i = 0; i < 8; i++) {
        if (HASH_HR[i] != expected[i]) {
            hash_ok = 0;
            uart_puts("U5 SHA-256 mismatch\n");
            break;
        }
    }
    if (hash_ok) {
        uart_puts("U5 SHA-256 \"abc\" OK\n");
    }

    if (!aes_ok || !hash_ok) {
        test_result = 1;
        test_complete = 1;
        for (;;) { __asm__ volatile ("wfi"); }
    }

    uart_puts("=== U5 smoke test passed ===\n");
    test_result = 0;
    test_complete = 1;
    for (;;) { __asm__ volatile ("wfi"); }
}

void Default_Handler(void)
{
    for (;;) { __asm__ volatile ("wfi"); }
}
