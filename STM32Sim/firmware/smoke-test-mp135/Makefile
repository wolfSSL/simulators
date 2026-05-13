# Makefile for the STM32Sim MP135 smoke-test firmware.
#
# Copyright (C) 2026 wolfSSL Inc.

CROSS    ?= arm-none-eabi-
CC       := $(CROSS)gcc
OBJCOPY  := $(CROSS)objcopy
SIZE     := $(CROSS)size

CFLAGS   := -mcpu=cortex-a7 -marm -mfpu=neon-vfpv4 -mfloat-abi=hard \
            -O0 -g -ffreestanding -nostartfiles -Wall -Wextra \
            -fno-common -ffunction-sections -fdata-sections
ASFLAGS  := -mcpu=cortex-a7 -marm -mfpu=neon-vfpv4 -mfloat-abi=hard \
            -g -ffreestanding
LDFLAGS  := -mcpu=cortex-a7 -marm -mfpu=neon-vfpv4 -mfloat-abi=hard \
            -nostartfiles -Wl,--gc-sections -T smoke.ld -Wl,-Map,smoke.map

OBJS     := startup.o mmu.o main.o
TARGET   := smoke.elf

all: $(TARGET)

$(TARGET): $(OBJS) smoke.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS)
	$(SIZE) $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S
	$(CC) $(ASFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) smoke.map

.PHONY: all clean
