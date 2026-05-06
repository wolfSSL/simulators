# Makefile for the STM32Sim smoke-test firmware.
#
# Copyright (C) 2026 wolfSSL Inc.

CROSS    ?= arm-none-eabi-
CC       := $(CROSS)gcc
OBJCOPY  := $(CROSS)objcopy
SIZE     := $(CROSS)size

CFLAGS   := -mcpu=cortex-m7 -mthumb -mfloat-abi=hard -mfpu=fpv5-d16 \
            -O0 -g -ffreestanding -nostartfiles -Wall -Wextra \
            -fno-common -ffunction-sections -fdata-sections
LDFLAGS  := -mcpu=cortex-m7 -mthumb -mfloat-abi=hard -mfpu=fpv5-d16 \
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
