/* startup.S
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Minimal MIPS32 startup for PIC32MZSim firmware. The Unicorn runner
 * jumps directly to `_reset` (set as the ELF entry point), so no boot
 * ROM trampoline is needed. Responsibilities:
 *   - install initial stack pointer
 *   - copy .data initialisers from FLASH (LMA) to SRAM (VMA)
 *   - zero .bss
 *   - call main()
 *   - spin forever if main returns
 */

    .set    noreorder
    .set    nomips16
    .section .reset, "ax"
    .globl  _reset
    .ent    _reset
_reset:
    la      $sp, _stack_top
    move    $fp, $sp
    move    $gp, $0

    /* Copy .data from LMA (flash) to VMA (SRAM). */
    la      $t0, _data_load
    la      $t1, _data_start
    la      $t2, _data_end
1:
    beq     $t1, $t2, 2f
    nop
    lw      $t3, 0($t0)
    sw      $t3, 0($t1)
    addiu   $t0, $t0, 4
    j       1b
    addiu   $t1, $t1, 4

2:
    /* Zero .bss. */
    la      $t0, _bss_start
    la      $t1, _bss_end
3:
    beq     $t0, $t1, 4f
    nop
    sw      $0, 0($t0)
    j       3b
    addiu   $t0, $t0, 4

4:
    /* Call main. */
    jal     main
    nop

    /* main returned (shouldn't): wait forever. */
5:
    j       5b
    nop
    .end    _reset
