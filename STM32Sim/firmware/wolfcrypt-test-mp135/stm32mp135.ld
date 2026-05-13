/* stm32mp135.ld - Memory map for the STM32MP135 wolfCrypt firmware
 * under stm32-sim. The MP135 has no internal flash, so the whole
 * application lives in DDR. The simulator maps a 512 MiB DDR window
 * at 0xC0000000 as plain RAM; we use the first 16 MiB for code,
 * data, BSS, heap, MMU translation tables, and exception stacks. */

ENTRY(_start)

MEMORY
{
    DDR (rwx) : ORIGIN = 0xC0000000, LENGTH = 16M
}

_Min_Heap_Size  = 2M;
_Min_Stack_Size = 256K;

SECTIONS
{
    .text :
    {
        . = ALIGN(4);
        KEEP(*(.text._start))
        *(.text*)
        *(.rodata*)
        *(.glue_7)
        *(.glue_7t)
        *(.eh_frame)
        . = ALIGN(4);
        _etext = .;
    } > DDR

    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > DDR

    .ARM.exidx :
    {
        __exidx_start = .;
        *(.ARM.exidx*)
        __exidx_end = .;
    } > DDR

    .preinit_array :
    {
        PROVIDE_HIDDEN(__preinit_array_start = .);
        KEEP(*(.preinit_array*))
        PROVIDE_HIDDEN(__preinit_array_end = .);
    } > DDR

    .init_array :
    {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array*))
        PROVIDE_HIDDEN(__init_array_end = .);
    } > DDR

    .fini_array :
    {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array*))
        PROVIDE_HIDDEN(__fini_array_end = .);
    } > DDR

    .data :
    {
        . = ALIGN(4);
        __data_start__ = .;
        *(.data*)
        . = ALIGN(4);
        __data_end__ = .;
    } > DDR

    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end__ = .;
    } > DDR

    /* ARMv7-A first-level translation table: 4096 word entries,
     * 16 KiB aligned. */
    .ttb (NOLOAD) : ALIGN(0x4000)
    {
        __ttb_start__ = .;
        . = . + 0x4000;
        __ttb_end__ = .;
    } > DDR

    .heap_stack (NOLOAD) :
    {
        . = ALIGN(8);
        PROVIDE(__heap_start__ = .);
        . = . + _Min_Heap_Size;
        PROVIDE(__heap_end__ = .);
        PROVIDE(end = __heap_end__);

        . = ALIGN(8);
        PROVIDE(__stack_start__ = .);
        . = . + _Min_Stack_Size;
        . = ALIGN(8);
        PROVIDE(__stack_top__ = .);
    } > DDR

    /DISCARD/ :
    {
        *(.ARM.attributes)
        *(.note*)
        *(.comment*)
    }
}

PROVIDE(_init = 0);
PROVIDE(_fini = 0);
