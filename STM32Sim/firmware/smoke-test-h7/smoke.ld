/* smoke.ld
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Linker script for the STM32Sim smoke-test firmware. Memory map
 * matches the STM32H753 chip configuration in stm32-sim-chips.
 */

ENTRY(Reset_Handler)

MEMORY
{
    FLASH    (rx)  : ORIGIN = 0x08000000, LENGTH = 2M
    DTCM     (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
    AXI_SRAM (rwx) : ORIGIN = 0x24000000, LENGTH = 512K
}

__stack_size__ = 0x4000;
__stack_top__  = ORIGIN(AXI_SRAM) + LENGTH(AXI_SRAM);

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
    } > AXI_SRAM AT > FLASH

    .bss (NOLOAD) : ALIGN(4)
    {
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
    } > AXI_SRAM

    /DISCARD/ :
    {
        *(.ARM.exidx*)
        *(.ARM.attributes)
        *(.note*)
        *(.comment*)
    }
}
