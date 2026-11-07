/* Multiboot v1 header with a.out kludge: the image is a flat binary loaded at 1 MiB. */
.section .mbh,"a"
.long 0x1BADB002, 0x00010000, -(0x1BADB002 + 0x00010000)
.long 0x100000, 0x100000, 0, _end, _start
.section .text.start,"ax"
.globl _start
_start:
    mov $0x9f000, %esp
    jmp kmain
