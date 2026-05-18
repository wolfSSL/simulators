/* mmu.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * 1 MiB-section identity-mapped MMU for the MP135 wolfCrypt firmware.
 * Identical in spirit to the smoke-test mmu.c: cover DDR as normal
 * memory, peripheral regions as Device, then enable the MMU.
 */

#include <stdint.h>

/* The linker script reserves a 16 KiB-aligned 16 KiB region for the
 * first-level translation table. Declare it as an array of u32 so the
 * compiler's bounds tracking can see the real size; with the bare
 * `extern uint32_t __ttb_start__` form, GCC's -Wstringop-overflow
 * (re-)inference treats `ttb[i] = 0` as a 16 KiB store into a 4-byte
 * object. */
extern uint32_t __ttb_start__[4096];

#define SECTION_NORMAL   (0x00020C0Eu)
#define SECTION_DEV_XN   (0x00020C16u)

#define MB               (1u << 20)

static void map_section(uint32_t *ttb, uint32_t va, uint32_t attrs)
{
    uint32_t idx = va >> 20;
    ttb[idx] = (va & 0xFFF00000u) | attrs;
}

static void map_range(uint32_t *ttb, uint32_t start, uint32_t end, uint32_t attrs)
{
    for (uint32_t va = start; va < end; va += MB) {
        map_section(ttb, va, attrs);
    }
}

void mmu_enable(void)
{
    uint32_t *ttb = __ttb_start__;

    for (int i = 0; i < 4096; i++) {
        ttb[i] = 0;
    }

    /* APB1 + nearby APB peripherals: UART4, USART3, I2C, etc. live
     * in this 1 MiB window. */
    map_section(ttb, 0x40000000u, SECTION_DEV_XN);

    /* AHB4 (RCC + co.) at 0x50000000. */
    map_section(ttb, 0x50000000u, SECTION_DEV_XN);

    /* AHB5 crypto/RNG/PKA at 0x54000000. */
    map_section(ttb, 0x54000000u, SECTION_DEV_XN);

    /* SYSRAM + SRAMs at 0x2FF00000 / 0x30000000. */
    map_section(ttb, 0x2FF00000u, SECTION_NORMAL);
    map_section(ttb, 0x30000000u, SECTION_NORMAL);

    /* DDR: 16 MiB matches the linker. */
    map_range(ttb, 0xC0000000u, 0xC1000000u, SECTION_NORMAL);

    __asm__ volatile ("dsb sy" ::: "memory");

    /* DACR: client (01) for domain 0. */
    __asm__ volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r"(0x55555555u));
    /* TTBR0 + TTBCR (use TTBR0 for whole 4 GiB). */
    __asm__ volatile ("mcr p15, 0, %0, c2, c0, 0" :: "r"((uint32_t)ttb));
    __asm__ volatile ("mcr p15, 0, %0, c2, c0, 2" :: "r"(0u));

    /* Invalidate everything before turning the MMU on. */
    __asm__ volatile ("mcr p15, 0, %0, c8, c7, 0" :: "r"(0u));
    __asm__ volatile ("mcr p15, 0, %0, c7, c5, 6" :: "r"(0u));
    __asm__ volatile ("mcr p15, 0, %0, c7, c5, 0" :: "r"(0u));
    __asm__ volatile ("dsb sy" ::: "memory");
    __asm__ volatile ("isb"   ::: "memory");

    uint32_t sctlr;
    __asm__ volatile ("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    sctlr |= 0x1u;
    sctlr &= ~(1u << 2);
    sctlr &= ~(1u << 12);
    __asm__ volatile ("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));
    __asm__ volatile ("dsb sy" ::: "memory");
    __asm__ volatile ("isb"   ::: "memory");
}
