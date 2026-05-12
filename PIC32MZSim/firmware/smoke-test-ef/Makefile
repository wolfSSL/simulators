## Makefile for the PIC32MZ EF smoke firmware.
##
## Copyright (C) 2026 wolfSSL Inc.

CROSS    ?= mipsel-linux-gnu-
CC       := $(CROSS)gcc
LD       := $(CROSS)gcc
OBJCOPY  := $(CROSS)objcopy
SIZE     := $(CROSS)size

COMMON      := ../common

# The smoke firmware is self-contained (no newlib): main.c provides
# local memcpy/memset/memcmp and does not touch stdio/malloc. This lets
# the cargo-test workflow build smoke.elf with only Debian's
# gcc-mipsel-linux-gnu cross compiler installed, no Docker / newlib
# bootstrap needed.
CFLAGS   := -EL -mips32r2 -G0 -mno-gpopt -ffreestanding -nostartfiles -nostdlib \
            -fno-pic -mno-abicalls \
            -fno-common -ffunction-sections -fdata-sections \
            -fno-builtin -fno-stack-protector \
            -Wall -Wextra -O0 -g \
            -D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x46 \
            -I$(COMMON)

LDFLAGS  := -EL -mips32r2 -G0 -mno-gpopt -ffreestanding -nostartfiles -nostdlib \
            -fno-pic -mno-abicalls -Wl,--gc-sections -static \
            -T $(COMMON)/pic32mz_link_kseg1.ld -Wl,-Map,smoke.map

OBJS     := main.o startup.o
TARGET   := smoke.elf

all: $(TARGET)

$(TARGET): $(OBJS) $(COMMON)/pic32mz_link_kseg1.ld
	$(LD) $(LDFLAGS) -o $@ $(OBJS) -lgcc
	$(SIZE) $@

main.o: main.c $(COMMON)/pic32mz_stubs.h
	$(CC) $(CFLAGS) -c -o $@ $<

startup.o: $(COMMON)/startup.S
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) smoke.map

.PHONY: all clean
