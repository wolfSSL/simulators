/* smoke.ld
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Linker script for the STM32Sim MP135 smoke-test firmware. The MP135
 * has no internal flash; the firmware lives in DDR (0xC0000000) and
 * Unicorn maps the whole DDR window as a writable RAM region. The
 * loader writes the ELF segments straight there, so we do not need a
 * .data-from-flash AT() trick.
 */

ENTRY(_start)

MEMORY
{
    DDR (rwx) : ORIGIN = 0xC0000000, LENGTH = 16M
}

__stack_size__ = 0x4000;

SECTIONS
{
    .text : ALIGN(4)
    {
        KEEP(*(.text._start))
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > DDR

    .data : ALIGN(4)
    {
        __data_start__ = .;
        *(.data*)
        . = ALIGN(4);
        __data_end__ = .;
    } > DDR

    .bss (NOLOAD) : ALIGN(4)
    {
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
    } > DDR

    /* The ARMv7-A first-level translation table is 16 KiB and must be
     * 16 KiB aligned. Place it after BSS, away from code. */
    .ttb (NOLOAD) : ALIGN(0x4000)
    {
        __ttb_start__ = .;
        . = . + 0x4000;
        __ttb_end__ = .;
    } > DDR

    .stack (NOLOAD) : ALIGN(8)
    {
        . = . + __stack_size__;
        __stack_top__ = .;
    } > DDR

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.attributes)
        *(.note*)
        *(.comment*)
    }
}
