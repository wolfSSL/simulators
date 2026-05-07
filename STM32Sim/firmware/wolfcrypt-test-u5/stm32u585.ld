/* stm32u585.ld - Memory map for STM32U585 under stm32-sim. Matches
 * the chip configuration in stm32-sim-chips/src/stm32u575.rs (which
 * also serves the stm32u585 chip alias). */

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 2048K
  RAM   (xrw) : ORIGIN = 0x20000000, LENGTH = 768K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_Min_Heap_Size = 64K;
_Min_Stack_Size = 64K;

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    *(.glue_7)
    *(.glue_7t)
    *(.eh_frame)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .ARM.extab :
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } > FLASH

  .ARM.exidx :
  {
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
  } > FLASH

  .preinit_array :
  {
    PROVIDE_HIDDEN(__preinit_array_start = .);
    KEEP(*(.preinit_array*))
    PROVIDE_HIDDEN(__preinit_array_end = .);
  } > FLASH

  .init_array :
  {
    PROVIDE_HIDDEN(__init_array_start = .);
    KEEP(*(SORT(.init_array.*)))
    KEEP(*(.init_array*))
    PROVIDE_HIDDEN(__init_array_end = .);
  } > FLASH

  .fini_array :
  {
    PROVIDE_HIDDEN(__fini_array_start = .);
    KEEP(*(SORT(.fini_array.*)))
    KEEP(*(.fini_array*))
    PROVIDE_HIDDEN(__fini_array_end = .);
  } > FLASH

  _sidata = LOADADDR(.data);

  .data :
  {
    . = ALIGN(4);
    __data_start__ = .;
    *(.data*)
    . = ALIGN(4);
    __data_end__ = .;
  } > RAM AT> FLASH

  .bss :
  {
    . = ALIGN(4);
    __bss_start__ = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    __bss_end__ = .;
  } > RAM

  .heap_stack (NOLOAD):
  {
    . = ALIGN(8);
    PROVIDE(__heap_start__ = .);
    . = . + _Min_Heap_Size;
    PROVIDE(__heap_end__ = .);
    PROVIDE(end = __heap_end__);
    . = ALIGN(8);
    PROVIDE(__stack_start__ = .);
    . = . + _Min_Stack_Size;
    PROVIDE(__stack_end__ = .);
  } > RAM
}

PROVIDE(_init = 0);
PROVIDE(_fini = 0);
