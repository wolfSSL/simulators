/* smoke.ld
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Linker script for the U5 smoke-test firmware. Memory map matches
 * the STM32U575 chip configuration in stm32-sim-chips.
 */

ENTRY(Reset_Handler)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 2M
    SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 768K
}

__stack_size__ = 0x4000;
__stack_top__  = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
    .isr_vector : ALIGN(4)
    {
        KEEP(*(.isr_vector))
    } > FLASH

    .text : ALIGN(4)
    {
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        __etext = .;
    } > FLASH

    .data : ALIGN(4)
    {
        __data_start__ = .;
        *(.data*)
        . = ALIGN(4);
        __data_end__ = .;
    } > SRAM AT > FLASH

    .bss (NOLOAD) : ALIGN(4)
    {
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
    } > SRAM

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.attributes)
        *(.note*)
        *(.comment*)
    }
}
