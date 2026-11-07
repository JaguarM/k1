ENTRY(_start)
SECTIONS {
  . = 0x100000;
  .text : { KEEP(*(.mbh)) *(.text.start) *(.text*) *(.rodata*) *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
  _end = .;
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
