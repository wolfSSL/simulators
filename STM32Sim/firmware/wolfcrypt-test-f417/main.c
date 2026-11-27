/* main.c - Entry point for wolfCrypt test on STM32F417 under stm32-sim.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STM32Sim.
 *
 * STM32Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STM32Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Runs the wolfCrypt test suite with output via USART2. wolfSSL's
 * `wolfcrypt_test()` returns 0 on success; this firmware also prints
 * the canonical pass/fail strings the simulator's run script greps
 * for, and writes test_result/test_complete in .data so the
 * simulator can poll completion via ELF symbol lookup.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* wolfCrypt test entry point */
extern int wolfcrypt_test(void *args);

/* USART2 (STM32F4 register layout: SR 0x00, DR 0x04, BRR 0x08, CR1 0x0C) */
#define USART2_BASE     0x40004400UL
#define USART2_SR       (*(volatile uint32_t *)(USART2_BASE + 0x00))
#define USART2_DR       (*(volatile uint32_t *)(USART2_BASE + 0x04))
#define USART2_BRR      (*(volatile uint32_t *)(USART2_BASE + 0x08))
#define USART2_CR1      (*(volatile uint32_t *)(USART2_BASE + 0x0C))

#define USART_CR1_UE    (1 << 13)
#define USART_CR1_TE    (1 << 3)
#define USART_SR_TXE    (1 << 7)

/* RCC register for enabling the USART2 clock */
#define RCC_BASE        0x40023800UL
#define RCC_APB1ENR     (*(volatile uint32_t *)(RCC_BASE + 0x40))
#define RCC_APB1ENR_USART2EN (1 << 17)

static void uart_init(void)
{
    /* Enable USART2 clock */
    RCC_APB1ENR |= RCC_APB1ENR_USART2EN;

    /* Configure USART2: 115200 baud at the 16 MHz HSI */
    USART2_BRR = 16000000 / 115200;
    USART2_CR1 = USART_CR1_UE | USART_CR1_TE;
}

static void uart_putc(char c)
{
    while (!(USART2_SR & USART_SR_TXE))
        ;
    USART2_DR = c;
}

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            uart_putc('\r');
        uart_putc(*s++);
    }
}

/* newlib _write syscall - redirects printf to UART */
int _write(int fd, const char *buf, int len)
{
    (void)fd;
    for (int i = 0; i < len; i++) {
        if (buf[i] == '\n')
            uart_putc('\r');
        uart_putc(buf[i]);
    }
    return len;
}

/* Heap management for malloc - required by printf with format strings */
extern char __heap_start__;
extern char __heap_end__;

void *_sbrk(ptrdiff_t incr)
{
    static char *heap_ptr = NULL;
    char *prev_heap_ptr;

    if (heap_ptr == NULL) {
        heap_ptr = &__heap_start__;
    }

    prev_heap_ptr = heap_ptr;

    if (heap_ptr + incr > &__heap_end__) {
        /* Out of heap memory */
        return (void *)-1;
    }

    heap_ptr += incr;
    return prev_heap_ptr;
}

/* Simple counter for time - used by GENSEED_FORTEST */
static volatile uint32_t tick_counter = 0;

/* time() stub for wolfSSL GENSEED_FORTEST */
#include <time.h>
time_t time(time_t *t)
{
    tick_counter += 12345;  /* Simple pseudo-random increment */
    time_t val = (time_t)tick_counter;
    if (t)
        *t = val;
    return val;
}

/* Result variables - the simulator polls these by ELF symbol address. */
volatile int test_result __attribute__((section(".data"))) = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;


int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    uart_init();
    uart_puts("\n\n=== Starting wolfCrypt test ===\n\n");

    test_result = wolfcrypt_test(NULL);

    if (test_result == 0) {
        uart_puts("\n\n=== wolfCrypt test passed! ===\n");
    } else {
        uart_puts("\n\n=== wolfCrypt test FAILED ===\n");
    }

    /* Set test_complete last: the simulator polls this between
     * instruction slices and exits as soon as it goes nonzero,
     * which would race with any output emitted afterwards. */
    test_complete = 1;

    /* Spin forever after the test completes */
    while (1) {
        __asm__ volatile ("wfi");
    }

    return test_result;
}

