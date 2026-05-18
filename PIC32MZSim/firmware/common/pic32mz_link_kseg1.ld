/* pic32mz_link_kseg1.ld
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * Linker script for PIC32MZSim firmware. KSEG1-only layout: code,
 * rodata, data, and bss all live in the uncached KSEG1 alias so the
 * simulator does not have to model cache coherency. Real silicon
 * would run code from KSEG0 (cached) and put DMA-touched buffers in
 * KSEG1; the wolfSSL pic32 port already tags streaming-hash buffers
 * with `__attribute__((coherent))` to force KSEG1, so running
 * everything uncached is a strict superset behaviourally.
 *
 *   FLASH  0xBD00_0000  2 MiB    (KSEG1 alias of phys 0x1D00_0000)
 *   SRAM   0xA000_0000  512 KiB  (KSEG1 alias of phys 0x0000_0000)
 *
 * The PIC32MZ boot vector lives in boot flash at 0xBFC0_0000; for our
 * sim runner we set the ELF entry point directly via Unicorn so the
 * boot ROM is not needed.
 */

OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(mips)
ENTRY(_reset)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0xBD000000, LENGTH = 2M
    SRAM  (rwx) : ORIGIN = 0xA0000000, LENGTH = 512K
}

_stack_size = 0x4000;
_stack_top  = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
    .text : ALIGN(16)
    {
        KEEP(*(.reset))
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        _etext = .;
    } > FLASH

    .data : ALIGN(4)
    {
        _data_start = .;
        *(.data*)
        *(.sdata*)
        *(.lit4 .lit8)
        . = ALIGN(4);
        _data_end = .;
    } > SRAM AT > FLASH

    _data_load = LOADADDR(.data);

    .bss (NOLOAD) : ALIGN(4)
    {
        _bss_start = .;
        *(.bss*)
        *(.sbss*)
        *(.scommon)
        *(COMMON)
        . = ALIGN(4);
        _bss_end = .;
    } > SRAM

    /* Heap for newlib's _sbrk / malloc. We do not size it via
     * `. += N` because the linker emits a program header for the
     * resulting NOLOAD section that confuses our simulator's ELF
     * loader (it reads the segment past the actual data range).
     * Instead the symbols mark the bounds and _sbrk uses everything
     * between _heap_start and _stack_top - _stack_size. */
    _heap_start = .;
    _heap_end = ORIGIN(SRAM) + LENGTH(SRAM) - _stack_size;

    /DISCARD/ :
    {
        *(.reginfo)
        *(.MIPS.abiflags)
        *(.note*)
        *(.comment*)
        *(.gnu.attributes)
        *(.eh_frame*)
        *(.gcc_except_table*)
    }
}
