/* startup.S
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Minimal Cortex-A7 ARM-mode reset path for the STM32Sim MP135
 * smoke-test firmware. Boots in SVC mode with the MMU off, sets the
 * stack, zeroes BSS, and jumps to main().
 *
 * Cortex-A7 does not boot from a vector table at address 0 the way a
 * Cortex-M does. Unicorn drops the CPU into emu_start at the ELF
 * entry point (the address of _start) in ARM mode, supervisor mode,
 * with interrupts disabled. So this file is intentionally small: no
 * vector table, no exception-mode stacks beyond SVC. main() enables
 * the MMU before exercising any peripherals.
 */

    .section .text._start, "ax"
    .global _start
    .arm
    .type _start, %function
_start:
    /* Make sure we are in SVC mode with FIQ/IRQ masked. */
    cpsid   if
    mrs     r0, cpsr
    bic     r0, r0, #0x1f
    orr     r0, r0, #0x13       /* SVC mode */
    msr     cpsr_c, r0

    /* Set the supervisor-mode stack. The linker reserves a 16 KiB
     * region whose top is __stack_top__. */
    ldr     sp, =__stack_top__

    /* Zero BSS. */
    ldr     r0, =__bss_start__
    ldr     r1, =__bss_end__
    mov     r2, #0
1:
    cmp     r0, r1
    bge     2f
    str     r2, [r0], #4
    b       1b
2:

    /* Hand off to C. main() never returns; if it does, spin. We
     * avoid wfe/wfi here because the Cortex-A7 model in Unicorn
     * decodes them as invalid instructions when there is no event
     * source. */
    bl      main
hang:
    b       hang

    .size _start, . - _start
