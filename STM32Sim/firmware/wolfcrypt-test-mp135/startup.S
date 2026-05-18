/* startup.S
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Cortex-A7 reset path for the STM32MP135 wolfCrypt firmware. Boots
 * in SVC mode, sets the supervisor stack, zeroes BSS, calls
 * __libc_init_array (so any C++/global ctors run), then main(). Same
 * pattern as the smoke-test-mp135 startup, with libc init added for
 * the wolfSSL build.
 */

    .section .text._start, "ax"
    .global _start
    .arm
    .type _start, %function
_start:
    cpsid   if
    mrs     r0, cpsr
    bic     r0, r0, #0x1f
    orr     r0, r0, #0x13       /* SVC mode */
    msr     cpsr_c, r0

    /* Grant PL0/PL1 access to coprocessors 10 and 11 (VFP/NEON), then
     * enable the FPU itself via FPEXC.EN. The firmware is compiled
     * with -mfpu=neon-vfpv4 -mfloat-abi=hard, so newlib's memchr and
     * other library routines emit NEON instructions; without this
     * the first vdup/vld traps as an undefined instruction. */
    mrc     p15, 0, r0, c1, c0, 2
    orr     r0, r0, #(0xf << 20)
    mcr     p15, 0, r0, c1, c0, 2
    isb
    mov     r0, #0x40000000
    vmsr    fpexc, r0

    ldr     sp, =__stack_top__

    /* Zero .bss. */
    ldr     r0, =__bss_start__
    ldr     r1, =__bss_end__
    mov     r2, #0
1:
    cmp     r0, r1
    bge     2f
    str     r2, [r0], #4
    b       1b
2:

    /* __libc_init_array runs preinit + init arrays. newlib's stubs
     * need this so any __attribute__((constructor)) work runs before
     * main(). */
    bl      __libc_init_array

    mov     r0, #0
    mov     r1, #0
    bl      main

hang:
    b       hang

    .size _start, . - _start
