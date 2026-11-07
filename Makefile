B := build

# The image: hand-written assembly (src/os.asm) -> flat multiboot binary
all: $(B)/os.bin

$(B)/gen.h $(B)/gen.inc: tools/gen.py www/index.html
	@mkdir -p $(B)
	python3 tools/gen.py www/index.html $(B)/gen.h

$(B)/os.bin: src/os.asm $(B)/gen.inc
	nasm -f bin -o $@ -l $(B)/os.lst src/os.asm
	@echo "image: $$(stat -c %s $@) bytes"

# asm crypto checked against pyca/cryptography on the host (32-bit process)
$(B)/test_asm: test/test_asm.c src/os.asm $(B)/gen.inc
	nasm -f elf32 -DHOST -o $(B)/os_host.o src/os.asm
	gcc -m32 -no-pie -fno-pie -O1 -o $@ test/test_asm.c $(B)/os_host.o

test: $(B)/test_asm $(B)/test_crypto
	python3 test/test_crypto.py $(B)/test_asm
	python3 test/test_crypto.py $(B)/test_crypto

# ---- reference C implementation (5876 -> 4584 bytes before the asm rewrite) ----
CC      := gcc
CFLAGS  := -m32 -march=i486 -Oz -fno-inline-functions-called-once -fno-tree-sra -malign-data=abi -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
           -fno-asynchronous-unwind-tables -fno-unwind-tables -fomit-frame-pointer \
           -mregparm=3 -mpreferred-stack-boundary=2 -fno-builtin -Wall -Wno-pointer-sign

c: $(B)/os_c.bin

$(B)/os.o: src/os.c src/crypto.h $(B)/gen.h
	$(CC) $(CFLAGS) -c $< -o $@

$(B)/start.o: src/start.S
	$(CC) -m32 -c $< -o $@

$(B)/os_c.elf: $(B)/start.o $(B)/os.o src/link.ld
	ld -m elf_i386 -T src/link.ld --gc-sections -o $@ $(B)/start.o $(B)/os.o

$(B)/os_c.bin: $(B)/os_c.elf
	objcopy -O binary $< $@
	@echo "C image: $$(stat -c %s $@) bytes"

# debug build of the C version: logs TCP segments / TLS records to COM1 (-serial stdio)
debug: $(B)/start.o $(B)/gen.h
	$(CC) $(CFLAGS) -DDEBUG -c src/os.c -o $(B)/osd.o
	ld -m elf_i386 -T src/link.ld --gc-sections -o $(B)/osd.elf $(B)/start.o $(B)/osd.o
	objcopy -O binary $(B)/osd.elf $(B)/osd.bin

$(B)/test_crypto: test/test_crypto.c src/crypto.h
	$(CC) -O1 -g -Wall -Wno-pointer-sign -o $@ $<

.PHONY: all test c debug
