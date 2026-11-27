/* STM32F405/407/415/417 memory map: 1 MiB flash, 128 KiB contiguous
 * SRAM1+SRAM2 at 0x20000000. Matches stm32-sim-chips/src/stm32f417.rs.
 * The 64 KiB CCM RAM at 0x10000000 is not used. */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM   (xrw) : ORIGIN = 0x20000000, LENGTH = 128K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_Min_Heap_Size = 16K;
_Min_Stack_Size = 8K;

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
    . = . + _Min_Stack_Size;
  } > RAM
}

PROVIDE(_init = 0);
PROVIDE(_fini = 0);
