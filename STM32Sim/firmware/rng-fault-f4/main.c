/* main.c
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

/* STM32F4 hardware-RNG fault test for wolfSSL's wc_GenerateSeed().
 *
 * 1. Sanity: pull a short seed with the RNG healthy; must return 0.
 * 2. Fault:  pull a long seed while the RNG fails part way through.
 *
 * A correct wc_GenerateSeed() returns from step 2, either with 0 (the
 * RNG recovered) or RNG_FAILURE_E (it did not). The bug this guards
 * against is the call never returning.
 *
 * How the RNG is made to fail depends on the build:
 *
 *   RNG_FAULT_BOARD (real STM32F407/F417 silicon): SYSCLK stays on HSI
 *   and the main PLL runs only to feed PLL48CLK, the RNG kernel clock.
 *   A SysTick interrupt switches the PLL off a few milliseconds into
 *   step 2, so the RNG loses its clock mid-fill (a genuine clock error:
 *   DRDY stops, CECS/CEIS latch). Built with RNG_FAULT_GLITCH_MS=<n>
 *   the PLL is switched back on n ms later instead, i.e. a transient
 *   clock glitch. The debugger reads the g_* variables back; the LEDs on
 *   PD12-PD15 show the same thing.
 *
 *   Default (stm32-sim): the simulator's --rng-fault option latches the
 *   SECS or CECS condition after a set number of DR reads.
 *
 * test_result is 0 when step 1 passed and step 2 returned; the console
 * line "RNG_FAULT ... fault=<ret>" carries the step 2 return code. */

#include <stdint.h>
#include <stddef.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "stm32f4xx.h"

#ifdef RNG_FAULT_BOARD
    /* Long enough (tens of ms at 16 MHz) that the SysTick fault lands
     * well inside the fill. */
    #define FAULT_BUF_SZ    32768
    #define FAULT_DELAY_MS  3
    #define HANG_MS         5000
#else
    #define FAULT_BUF_SZ    1024
#endif
#define SANITY_SZ           64

#define STAGE_INIT          0
#define STAGE_SANITY        1
#define STAGE_FAULT         2
#define STAGE_DONE          3

/* Polled by stm32-sim through the ELF symbol table. */
volatile int test_result __attribute__((section(".data"))) = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

/* Diagnostics, read back with the debugger on hardware. */
volatile uint32_t g_stage = STAGE_INIT;
volatile int32_t  g_sanity_ret = 1;
volatile int32_t  g_fault_ret = 1;
volatile uint32_t g_tick;
volatile uint32_t g_fault_tick;
volatile uint32_t g_fault_fired_tick;
volatile uint32_t g_rng_sr_after_fault;
volatile uint32_t g_return_tick;
volatile uint32_t g_hung;

static byte sanity_buf[SANITY_SZ];
static byte fault_buf[FAULT_BUF_SZ];

/* ---- console (USART2, F4 register layout) ------------------------------ */

static void uart_init(void)
{
    RCC->APB1ENR |= RCC_APB1ENR_USART2EN;
    USART2->BRR = 16000000U / 115200U;
    USART2->CR1 = USART_CR1_UE | USART_CR1_TE;
}

static void uart_putc(char c)
{
    while ((USART2->SR & USART_SR_TXE) == 0U) {
    }
    USART2->DR = (uint32_t)(unsigned char)c;
}

static void uart_puts(const char* s)
{
    while (*s != '\0') {
        if (*s == '\n') {
            uart_putc('\r');
        }
        uart_putc(*s++);
    }
}

static void uart_putd(int32_t v)
{
    char buf[12];
    int i = 0;
    uint32_t u;

    if (v < 0) {
        uart_putc('-');
        u = (uint32_t)0 - (uint32_t)v;
    }
    else {
        u = (uint32_t)v;
    }
    do {
        buf[i++] = (char)('0' + (u % 10U));
        u /= 10U;
    } while (u != 0U);
    while (i > 0) {
        uart_putc(buf[--i]);
    }
}

/* ---- newlib hooks ------------------------------------------------------ */

extern char __heap_start__;
extern char __heap_end__;

void* _sbrk(ptrdiff_t incr)
{
    static char* heap_ptr = NULL;
    char* prev;

    if (heap_ptr == NULL) {
        heap_ptr = &__heap_start__;
    }
    prev = heap_ptr;
    if (heap_ptr + incr > &__heap_end__) {
        return (void*)-1;
    }
    heap_ptr += incr;
    return prev;
}

/* ---- RNG kernel clock --------------------------------------------------- */

/* SYSCLK stays on HSI (16 MHz). Run the main PLL from HSI purely for the
 * 48 MHz PLL48CLK: 16 MHz / M(16) * N(336) = 336 MHz VCO, / Q(7) = 48 MHz.
 * PLLP is unused because SYSCLK does not come from the PLL, which is what
 * lets the fault below stop the PLL without stopping the core. */
static void pll48_start(void)
{
    uint32_t cfg = RCC->PLLCFGR;

    cfg &= ~(RCC_PLLCFGR_PLLM_Msk | RCC_PLLCFGR_PLLN_Msk |
             RCC_PLLCFGR_PLLP_Msk | RCC_PLLCFGR_PLLSRC_Msk |
             RCC_PLLCFGR_PLLQ_Msk);
    cfg |= (16U << RCC_PLLCFGR_PLLM_Pos) | (336U << RCC_PLLCFGR_PLLN_Pos) |
           (7U << RCC_PLLCFGR_PLLQ_Pos);
    RCC->PLLCFGR = cfg;
    RCC->CR |= RCC_CR_PLLON;
    while ((RCC->CR & RCC_CR_PLLRDY) == 0U) {
    }
}

#ifdef RNG_FAULT_BOARD

/* ---- STM32F4DISCOVERY LEDs ----------------------------------------------- */

#define LED_GREEN   12  /* sanity seed passed */
#define LED_ORANGE  13  /* faulted seed call returned */
#define LED_RED     14  /* faulted seed call hung */
#define LED_BLUE    15  /* heartbeat */

static void leds_init(void)
{
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIODEN;
    (void)RCC->AHB1ENR;
    GPIOD->MODER |= (1U << (LED_GREEN * 2)) | (1U << (LED_ORANGE * 2)) |
                    (1U << (LED_RED * 2)) | (1U << (LED_BLUE * 2));
}

static void led_on(int pin)
{
    GPIOD->BSRR = 1U << pin;
}

static void led_toggle(int pin)
{
    GPIOD->ODR ^= 1U << pin;
}

void SysTick_Handler(void)
{
    uint32_t t = ++g_tick;

    if (g_fault_tick != 0U && t == g_fault_tick) {
        /* Take the RNG kernel clock away mid-fill. */
        RCC->CR &= ~RCC_CR_PLLON;
        g_fault_fired_tick = t;
    }
#ifdef RNG_FAULT_GLITCH_MS
    if (g_fault_fired_tick != 0U &&
            t == g_fault_fired_tick + RNG_FAULT_GLITCH_MS) {
        RCC->CR |= RCC_CR_PLLON; /* the clock comes back */
    }
#endif
    if (g_fault_fired_tick != 0U && t == g_fault_fired_tick + 100U) {
        g_rng_sr_after_fault = RNG->SR;
    }
    if (g_stage == STAGE_FAULT && g_fault_fired_tick != 0U &&
            (t - g_fault_fired_tick) > HANG_MS) {
        g_hung = 1;
        led_on(LED_RED);
    }
    if ((t % 250U) == 0U) {
        led_toggle(LED_BLUE);
    }
}

#endif /* RNG_FAULT_BOARD */

int main(void)
{
    OS_Seed os;
    int i;
    int nonzero = 0;

    XMEMSET(&os, 0, sizeof(os));
    uart_init();
    pll48_start();
#ifdef RNG_FAULT_BOARD
    leds_init();
    (void)SysTick_Config(16000U); /* 1 kHz from the 16 MHz HSI */
#endif

#ifdef WOLFSSL_STM32_RNG_NOLIB
    uart_puts("\n=== RNG fault test: WOLFSSL_STM32_RNG_NOLIB arm ===\n");
#else
    uart_puts("\n=== RNG fault test: StdPeriph arm ===\n");
#endif

    g_stage = STAGE_SANITY;
    g_sanity_ret = wc_GenerateSeed(&os, sanity_buf, sizeof(sanity_buf));
    for (i = 0; i < (int)sizeof(sanity_buf); i++) {
        nonzero |= sanity_buf[i];
    }
    if (g_sanity_ret == 0 && nonzero == 0) {
        g_sanity_ret = -1; /* all-zero "seed": RNG not actually running */
    }
#ifdef RNG_FAULT_BOARD
    if (g_sanity_ret == 0) {
        led_on(LED_GREEN);
    }
#endif
    uart_puts("sanity seed ret=");
    uart_putd(g_sanity_ret);
    uart_puts("\n");

    uart_puts("faulted seed: calling wc_GenerateSeed()\n");
    g_stage = STAGE_FAULT;
#ifdef RNG_FAULT_BOARD
    g_fault_tick = g_tick + FAULT_DELAY_MS;
#endif
    g_fault_ret = wc_GenerateSeed(&os, fault_buf, sizeof(fault_buf));
    g_stage = STAGE_DONE;
#ifdef RNG_FAULT_BOARD
    g_return_tick = g_tick;
    led_on(LED_ORANGE);
#endif

    uart_puts("RNG_FAULT sanity=");
    uart_putd(g_sanity_ret);
    uart_puts(" fault=");
    uart_putd(g_fault_ret);
    uart_puts("\n");

    if (g_sanity_ret == 0 &&
            (g_fault_ret == 0 || g_fault_ret == RNG_FAILURE_E)) {
        test_result = 0;
        uart_puts("=== RNG fault test returned ===\n");
    }
    else {
        test_result = 1;
        uart_puts("=== RNG fault test FAILED ===\n");
    }
    /* Last: stm32-sim exits as soon as this goes nonzero. */
    test_complete = 1;

    for (;;) {
        __asm__ volatile ("wfi");
    }
    return 0;
}
