# Makefile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of TROPIC01Sim.
#
# TROPIC01Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Builds the conformance probe for POSIX (libtropic TCP HAL, wolfCrypt CAL):
#
#   make LIBTROPIC_DIR=/path/to/libtropic WOLFSSL_DIR=/path/to/wolfssl
#
# libtropic 4.2.0 (the release the baseline was recorded with) and a wolfSSL
# release are expected. The binary is build/tr01_conf.

LIBTROPIC_DIR ?=
WOLFSSL_DIR   ?=
BUILD         ?= build

ifeq ($(LIBTROPIC_DIR),)
$(error Set LIBTROPIC_DIR to a libtropic checkout)
endif
ifeq ($(WOLFSSL_DIR),)
$(error Set WOLFSSL_DIR to a wolfSSL checkout)
endif

CC ?= cc

LT_DEFS = -DLT_HELPERS -DLT_SILICON_REV_ACAB -DLT_CRC_ERR_RETRY_ATTEMPTS=3 \
          -DLT_L1_READ_MAX_TRIES=50 -DLT_L1_READ_RETRY_DELAY_MS=25 \
          -DLT_L1_SPI_TIMEOUT_MS=70 -DLT_L1_INT_TIMEOUT_MS=200 \
          -DLT_LOG_ENABLE_DEBUG=0 -DLT_LOG_ENABLE_INFO=0 \
          -DLT_LOG_ENABLE_WARN=0 -DLT_LOG_ENABLE_ERROR=1
INC = -I. -I$(WOLFSSL_DIR) -I$(LIBTROPIC_DIR)/include -I$(LIBTROPIC_DIR)/src \
      -I$(LIBTROPIC_DIR)/cal/wolfcrypt -I$(LIBTROPIC_DIR)/hal/posix/tcp
CFLAGS += $(INC) -DWOLFSSL_USER_SETTINGS $(LT_DEFS) -D_DEFAULT_SOURCE \
          -O1 -g -std=gnu11 -Wall -Wno-unused-function

LT_SRC = $(addprefix $(LIBTROPIC_DIR)/src/, \
           libtropic.c lt_crc16.c lt_port_wrap.c lt_l1.c libtropic_l2.c \
           lt_l2_frame_check.c lt_l3_process.c libtropic_l3.c lt_hkdf.c \
           lt_asn1_der.c libtropic_default_sh0_keys.c lt_tr01_attrs.c \
           libtropic_secure_memzero.c) \
         $(wildcard $(LIBTROPIC_DIR)/cal/wolfcrypt/*.c)
LT_HAL = $(LIBTROPIC_DIR)/hal/posix/tcp/libtropic_port_posix_tcp.c
WC_SRC = $(addprefix $(WOLFSSL_DIR)/wolfcrypt/src/, \
           aes.c sha256.c sha512.c hmac.c hash.c random.c curve25519.c \
           fe_operations.c ed25519.c ge_operations.c ecc.c sp_int.c \
           wolfmath.c memory.c error.c logging.c wc_port.c asn.c coding.c \
           kdf.c signature.c)
SRC = tr01_conf.c plat_posix.c $(LT_SRC) $(WC_SRC)

OBJ = $(foreach s,$(SRC),$(BUILD)/obj/$(notdir $(s:.c=.o))) $(BUILD)/obj/lt_hal.o
vpath %.c $(sort $(dir $(SRC)))

.PHONY: all clean
all: $(BUILD)/tr01_conf

$(BUILD)/obj/%.o: %.c user_settings.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# The probe traces L1 traffic by wrapping the HAL's SPI functions
$(BUILD)/obj/lt_hal.o: $(LT_HAL) user_settings.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -include strings.h \
	    -Dlt_port_spi_transfer=lt_port_spi_transfer_real \
	    -Dlt_port_spi_csn_low=lt_port_spi_csn_low_real \
	    -Dlt_port_spi_csn_high=lt_port_spi_csn_high_real -c $< -o $@

$(BUILD)/tr01_conf: $(OBJ)
	$(CC) -o $@ $(OBJ) -lm

clean:
	rm -rf $(BUILD)
