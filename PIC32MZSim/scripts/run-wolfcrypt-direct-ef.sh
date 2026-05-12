#!/bin/bash
# Copyright (C) 2026 wolfSSL Inc.
#
# Build wolfSSL with the WOLFSSL_MICROCHIP_PIC32MZ direct-register port
# for PIC32MZ EF, link the wolfcrypt-test-direct-ef firmware against
# it, and run the resulting ELF through the PIC32MZSim simulator.
set -eu

: "${WOLFSSL:=/opt/wolfssl}"
WOLFSSL_SRC=/tmp/wolfssl-src-ef
WOLFSSL_BUILD=/opt/wolfssl-build-ef
FW=/app/firmware/wolfcrypt-test-direct-ef
COMMON=/app/firmware/common

if [ ! -d "$WOLFSSL" ]; then
    echo "wolfSSL tree not mounted at $WOLFSSL - aborting." >&2
    exit 2
fi

# The CI mount is read-only; copy to a writable scratch dir.
rm -rf "$WOLFSSL_SRC"
cp -a "$WOLFSSL" "$WOLFSSL_SRC"

# Build libwolfssl.a directly (bypasses autoconf - see
# build-wolfssl-static.sh for the rationale).
mkdir -p "$WOLFSSL_BUILD"
/app/scripts/build-wolfssl-static.sh "$WOLFSSL_SRC" "$WOLFSSL_BUILD" \
    "-D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x46 \
     -DWOLFSSL_PIC32MZSIM_DIRECT \
     -include $COMMON/user_settings.h \
     -include $COMMON/pic32mz_stubs.h \
     -I$COMMON -isystem $COMMON/xc-include"

# Build the firmware ELF.
make -C "$FW" \
    WOLFSSL_DIR="$WOLFSSL_SRC" \
    WOLFSSL_LIB="$WOLFSSL_BUILD/libwolfssl.a"

# Run the simulator.
exec /usr/local/bin/pic32mz-sim \
    --chip pic32mz2048efh144 \
    --timeout 600 \
    --exit-on test_complete \
    --result-symbol test_result \
    "$FW/wolfcrypt.elf"
