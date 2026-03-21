/* STM32H563ZI Linker Script (TrustZone disabled)
 *
 * Memory Map (TZEN=0):
 *   FLASH: 2048KB @ 0x08000000 (minus 128KB NV = 1920KB code)
 *   SRAM:  640KB @ 0x20000000 (contiguous SRAM1+SRAM2+SRAM3)
 *
 * NV flash storage: last 128KB (0x081E0000 - 0x081FFFFF)
 */

ENTRY(Reset_Handler)

_estack = ORIGIN(RAM) + LENGTH(RAM);
_sidata = LOADADDR(.data);

_Min_Heap_Size  = 0x30000;  /* 192KB heap for FWTPM_CTX + wolfCrypt */
_Min_Stack_Size = 0x10000;  /* 64KB stack (RSA keygen needs headroom) */

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1920K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 640K
}

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
    *(.text)
    *(.text*)
    *(.glue_7)
    *(.glue_7t)
    *(.eh_frame)
    *(.ARM.extab* .gnu.linkonce.armextab.*)
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;
  } > FLASH

  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)
    *(.rodata*)
    . = ALIGN(4);
  } > FLASH

  .preinit_array :
  {
    __preinit_array_start = .;
    KEEP(*(.preinit_array*))
    __preinit_array_end = .;
  } > FLASH

  .init_array :
  {
    __init_array_start = .;
    KEEP(*(SORT(.init_array.*)))
    KEEP(*(.init_array*))
    __init_array_end = .;
  } > FLASH

  .fini_array :
  {
    __fini_array_start = .;
    KEEP(*(SORT(.fini_array.*)))
    KEEP(*(.fini_array*))
    __fini_array_end = .;
  } > FLASH

  .data :
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data)
    *(.data*)
    *(.RamFunc)
    *(.RamFunc*)

    . = ALIGN(4);
    _edata = .;
  } > RAM AT> FLASH

  .bss (NOLOAD) :
  {
    _sbss = .;
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;
    __bss_end__ = _ebss;
  } > RAM

  ._user_heap_stack (NOLOAD) :
  {
    . = ALIGN(8);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _Min_Heap_Size;
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
  } > RAM

  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 : { *(.ARM.attributes) }
}
