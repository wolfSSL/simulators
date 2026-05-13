/* mmu.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Minimal ARMv7-A MMU bring-up for the MP135 smoke-test firmware.
 * Builds a flat first-level (1 MiB section) translation table that
 * identity-maps everything the firmware touches, then enables the
 * MMU.
 *
 * The wolfSSL example's system_stm32mp13xx_A7_freeRTOS.c does a much
 * more elaborate setup (two-level tables, write-back regions vs
 * Device regions split across many ranges). For the simulator we only
 * need enough mapping to satisfy Unicorn's QEMU-style MMU walk: any
 * page the firmware reads or writes must resolve to a valid VA->PA
 * mapping.
 */

#include <stdint.h>

/* The linker script reserves a 16 KiB-aligned 16 KiB region for the
 * first-level translation table. Declare it as an array of u32 so the
 * compiler's bounds tracking can see the real size. */
extern uint32_t __ttb_start__[4096];

/* AP[2:0] = 011 (full access at PL0/PL1)
 * TEX[2:0] = 001 + B=1 + C=1 -> Normal Outer/Inner Write-Back, Write-Allocate
 * S = 1 (shareable), nG = 0, NS = 0
 * Section bit pattern (PXN=0, NS=0, nG=0, S=1, AP[2]=0, TEX=001,
 *                      AP[1:0]=11, IMP=0, Domain=0, XN=0, C=1, B=1, [1:0]=10)
 *
 * Bits (from MSB):
 *   31:20 base address
 *   18    nG = 0
 *   17    S  = 1
 *   16    AP[2] = 0
 *   15    TEX[2] = 0
 *   14:12 TEX[1:0] (low two bits in 14:12 region's low bits; bit 12 is TEX[0])
 *   11:10 AP[1:0] = 11
 *    9    IMP = 0
 *    8:5  Domain = 0
 *    4    XN = 0
 *    3    C  = 1
 *    2    B  = 1
 *    1:0  = 10 (section descriptor)
 */
#define SECTION_NORMAL   (0x00020C0E)  /* S=1, AP=11, TEX=001, C=1, B=1, type=10 */
#define SECTION_DEVICE   (0x00020C06)  /* S=1, AP=11, TEX=000, C=0, B=1, type=10 */
#define SECTION_DEV_XN   (0x00020C16)  /* same as DEVICE plus XN=1 */

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

    /* APB1 (UART4 lives here): Device, no-execute. Cover the whole
     * 1 MiB section that contains 0x40010000. */
    map_section(ttb, 0x40000000u, SECTION_DEV_XN);

    /* RCC and friends at 0x50000000 (AHB4). */
    map_section(ttb, 0x50000000u, SECTION_DEV_XN);

    /* AHB5 crypto/RNG/PKA at 0x54000000. */
    map_section(ttb, 0x54000000u, SECTION_DEV_XN);

    /* SYSRAM + SRAMs around 0x2FF00000-0x30100000. Just cover both
     * sections; the firmware does not use them but a stray access
     * should not fault here. */
    map_section(ttb, 0x2FF00000u, SECTION_NORMAL);
    map_section(ttb, 0x30000000u, SECTION_NORMAL);

    /* DDR: cover the 16 MiB we actually link into. Anything beyond is
     * unmapped, which is fine - Unicorn would fault us if we ran off. */
    map_range(ttb, 0xC0000000u, 0xC1000000u, SECTION_NORMAL);

    /* Drain any pending writes to the page table. */
    __asm__ volatile ("dsb sy" ::: "memory");

    /* Domain access: client (01) for domain 0. */
    __asm__ volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r"(0x55555555u));

    /* TTBR0 = ttb; the low bits are RGN/IRGN/S which we leave 0 for
     * a non-cached table walk. Good enough for Unicorn. */
    __asm__ volatile ("mcr p15, 0, %0, c2, c0, 0" :: "r"((uint32_t)ttb));

    /* TTBCR = 0: use TTBR0 for the full 4 GiB address space. */
    __asm__ volatile ("mcr p15, 0, %0, c2, c0, 2" :: "r"(0u));

    /* Invalidate TLB, branch predictor, and I-cache before turning
     * the MMU on. */
    __asm__ volatile ("mcr p15, 0, %0, c8, c7, 0" :: "r"(0u));   /* TLBIALL */
    __asm__ volatile ("mcr p15, 0, %0, c7, c5, 6" :: "r"(0u));   /* BPIALL */
    __asm__ volatile ("mcr p15, 0, %0, c7, c5, 0" :: "r"(0u));   /* ICIALLU */
    __asm__ volatile ("dsb sy" ::: "memory");
    __asm__ volatile ("isb"   ::: "memory");

    /* SCTLR: set M=1 (MMU enable). Leave caches off for the smoke
     * test - we do not care about performance and avoiding cache
     * maintenance keeps the firmware simple. */
    uint32_t sctlr;
    __asm__ volatile ("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    sctlr |= 0x1u;             /* M */
    sctlr &= ~(1u << 2);       /* C off */
    sctlr &= ~(1u << 12);      /* I off */
    __asm__ volatile ("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));
    __asm__ volatile ("dsb sy" ::: "memory");
    __asm__ volatile ("isb"   ::: "memory");
}
