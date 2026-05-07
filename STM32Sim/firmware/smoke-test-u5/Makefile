# Makefile for the STM32U575 smoke-test firmware.
#
# Copyright (C) 2026 wolfSSL Inc.

CROSS    ?= arm-none-eabi-
CC       := $(CROSS)gcc
SIZE     := $(CROSS)size

CFLAGS   := -mcpu=cortex-m33 -mthumb \
            -O0 -g -ffreestanding -nostartfiles -Wall -Wextra \
            -fno-common -ffunction-sections -fdata-sections
LDFLAGS  := -mcpu=cortex-m33 -mthumb \
            -nostartfiles -Wl,--gc-sections -T smoke.ld -Wl,-Map,smoke.map

OBJS     := main.o vectors.o
TARGET   := smoke.elf

all: $(TARGET)

$(TARGET): $(OBJS) smoke.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS)
	$(SIZE) $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) smoke.map

.PHONY: all clean
