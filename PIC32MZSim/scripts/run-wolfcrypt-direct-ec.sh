#!/bin/bash
# Copyright (C) 2026 wolfSSL Inc.
#
# Same as run-wolfcrypt-direct-ef.sh but builds wolfSSL with the EC
# feature-set defines so PIC32_NO_OUT_SWAP is enabled, and runs the
# resulting ELF against the EC chip config (CryptoEngine::for_ec()).
set -eu

: "${WOLFSSL:=/opt/wolfssl}"
WOLFSSL_SRC=/tmp/wolfssl-src-ec
WOLFSSL_BUILD=/opt/wolfssl-build-ec
FW=/app/firmware/wolfcrypt-test-direct-ec
COMMON=/app/firmware/common

if [ ! -d "$WOLFSSL" ]; then
    echo "wolfSSL tree not mounted at $WOLFSSL - aborting." >&2
    exit 2
fi

rm -rf "$WOLFSSL_SRC"
cp -a "$WOLFSSL" "$WOLFSSL_SRC"

mkdir -p "$WOLFSSL_BUILD"
/app/scripts/build-wolfssl-static.sh "$WOLFSSL_SRC" "$WOLFSSL_BUILD" \
    "-D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x43 \
     -DWOLFSSL_PIC32MZSIM_DIRECT \
     -include $COMMON/user_settings.h \
     -include $COMMON/pic32mz_stubs.h \
     -I$COMMON -isystem $COMMON/xc-include"

make -C "$FW" \
    WOLFSSL_DIR="$WOLFSSL_SRC" \
    WOLFSSL_LIB="$WOLFSSL_BUILD/libwolfssl.a"

exec /usr/local/bin/pic32mz-sim \
    --chip pic32mz2048ech144 \
    --timeout 600 \
    --exit-on test_complete \
    --result-symbol test_result \
    "$FW/wolfcrypt.elf"
