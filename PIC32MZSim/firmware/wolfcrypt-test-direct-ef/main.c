/* main.c - wolfCrypt test driver, PIC32MZ EF direct-register port
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Runs wolfSSL's full `wolfcrypt_test()` self-test via the PIC32 direct
 * crypto-engine port (MICROCHIP_PIC32 + WOLFSSL_MICROCHIP_PIC32MZ). The
 * simulator's runner polls `test_complete` / `test_result` to surface
 * pass/fail and stdout from wolfcrypt_test() is routed to UART2 via
 * newlib's _write syscall in firmware/common/syscalls.c.
 */

#include <stdint.h>

#include "pic32mz_stubs.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

extern int wolfcrypt_test(void *args);

volatile int test_result   __attribute__((section(".data"))) = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') U2TXREG = (uint32_t)'\r';
        U2TXREG = (uint32_t)(unsigned char)*s++;
    }
}

int main(void)
{
    U2BRG  = 50;
    U2MODE = (1u << 15);
    U2STA  = (1u << 10);

    uart_puts("\n=== wolfCrypt PIC32MZ EF (direct) ===\n");

    int rc = wolfCrypt_Init();
    if (rc != 0) {
        uart_puts("wolfCrypt_Init FAILED\n");
        test_result = rc;
        test_complete = 1;
        for (;;) { __asm__ volatile ("nop"); }
    }

    rc = wolfcrypt_test(NULL);

    if (rc == 0) {
        uart_puts("=== wolfCrypt test passed! ===\n");
    } else {
        uart_puts("=== wolfCrypt test FAILED ===\n");
    }

    wolfCrypt_Cleanup();

    test_result = rc;
    test_complete = 1;
    for (;;) { __asm__ volatile ("nop"); }
    return rc;
}
