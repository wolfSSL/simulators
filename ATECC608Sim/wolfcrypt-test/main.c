/*
 * wolfCrypt test harness for the ATECC608A simulator.
 *
 * Registers our TCP-based cryptoauthlib HAL with wolfSSL, then hands off
 * to wolfCrypt's built-in `wolfcrypt_test()` suite. The test suite
 * exercises every subsystem wolfSSL supports; for ATECC608A builds it
 * naturally restricts itself to the subset the hardware can handle
 * (P-256 ECDSA, ECDH, SHA, RNG, ...).
 */
#include <stdio.h>
#include <stdlib.h>

#include "cryptoauthlib.h"
#include "hal_tcp.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/port/atmel/atmel.h>
#include <wolfssl/wolfcrypt/wc_port.h>

extern int wolfcrypt_test(void* args);

/* wolfSSL's built-in atmel_ecc_alloc serves a single ECC_SLOT_ECDHE_PRIV
 * slot, so wolfcrypt_test()'s ECC suite (which makes several hardware
 * keys concurrently) runs out on the second call. Our simulator has 8
 * ECC-capable slots; round-robin them. */
static int sim_slot_alloc(int type) {
    static int next = 0;
    (void)type;
    int slot = next;
    next = (next + 1) % 8;
    return slot;
}

static void sim_slot_dealloc(int slot) {
    (void)slot;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    static ATCAIfaceCfg cfg;
    hal_tcp_make_cfg(&cfg);
    if (wolfCrypt_ATECC_SetConfig(&cfg) != 0) {
        fprintf(stderr, "wolfCrypt_ATECC_SetConfig failed\n");
        return 1;
    }
    atmel_set_slot_allocator(sim_slot_alloc, sim_slot_dealloc);

    /* Explicit Init so we can detect ATECC init failures before the test
     * suite's own wolfCrypt_Init swallows them. atcab_init is idempotent. */
    int init_rc = wolfCrypt_Init();
    if (init_rc != 0) {
        fprintf(stderr, "wolfCrypt_Init failed: %d\n", init_rc);
        return 1;
    }

    printf("=== wolfCrypt test suite vs. ATECC608A simulator ===\n");
    int rc = wolfcrypt_test(NULL);
    if (rc != 0) {
        fprintf(stderr, "wolfcrypt_test() returned %d\n", rc);
        return rc;
    }
    printf("\nAll wolfCrypt tests passed\n");
    return 0;
}
