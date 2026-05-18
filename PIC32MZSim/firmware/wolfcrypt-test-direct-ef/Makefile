## Makefile for wolfCrypt test firmware, PIC32MZ EF + direct-register port.
##
## Copyright (C) 2026 wolfSSL Inc.

CROSS    ?= mipsel-linux-gnu-
CC       := $(CROSS)gcc
LD       := $(CROSS)gcc
SIZE     := $(CROSS)size

COMMON      := ../common
NEWLIB_DIR  ?= /opt/newlib-mipsel/mipsel-unknown-elf
WOLFSSL_DIR ?= /opt/wolfssl
WOLFSSL_LIB ?= /opt/wolfssl-build/libwolfssl.a

CFLAGS   := -EL -mips32r2 -G0 -mno-gpopt -ffreestanding -nostartfiles -nostdlib \
            -fno-pic -mno-abicalls \
            -fno-common -ffunction-sections -fdata-sections \
            -fno-builtin -fno-stack-protector \
            -Wall -Wextra -O0 -g \
            -D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x46 \
            -DWOLFSSL_PIC32MZSIM_DIRECT \
            -DWOLFSSL_USER_SETTINGS \
            -include $(COMMON)/user_settings.h \
            -include $(COMMON)/pic32mz_stubs.h \
            -I$(COMMON) -isystem $(COMMON)/xc-include \
            -isystem $(NEWLIB_DIR)/include \
            -I$(WOLFSSL_DIR)

LDFLAGS  := -EL -mips32r2 -G0 -mno-gpopt -ffreestanding -nostartfiles -nostdlib \
            -fno-pic -mno-abicalls -Wl,--gc-sections -static \
            -L$(NEWLIB_DIR)/lib \
            -T $(COMMON)/pic32mz_link_kseg1.ld -Wl,-Map,wolfcrypt.map

OBJS     := main.o startup.o syscalls.o
TARGET   := wolfcrypt.elf

all: $(TARGET)

$(TARGET): $(OBJS) $(COMMON)/pic32mz_link_kseg1.ld
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(WOLFSSL_LIB) -lc -lgcc
	$(SIZE) $@

main.o: main.c $(COMMON)/pic32mz_stubs.h $(COMMON)/user_settings.h
	$(CC) $(CFLAGS) -c -o $@ $<

startup.o: $(COMMON)/startup.S
	$(CC) $(CFLAGS) -c -o $@ $<

syscalls.o: $(COMMON)/syscalls.c $(COMMON)/pic32mz_stubs.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) wolfcrypt.map

.PHONY: all clean
