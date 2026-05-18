#!/bin/bash
# Copyright (C) 2026 wolfSSL Inc.
#
# Build wolfSSL + the Microchip Harmony 3 crypto driver for PIC32MZ EC,
# link the wolfcrypt-test-harmony-ec firmware, and run it through the
# simulator. The Harmony driver tree is baked into the image at
# /opt/harmony/crypto by Dockerfile.wolfcrypt-harmony.
set -eu

: "${WOLFSSL:=/opt/wolfssl}"
: "${HARMONY_CRYPTO:=/opt/harmony/crypto}"
WOLFSSL_SRC=/tmp/wolfssl-src-harmony-ec
WOLFSSL_BUILD=/opt/wolfssl-build-harmony-ec
HARMONY_BUILD=/opt/harmony-build-ec
FW=/app/firmware/wolfcrypt-test-harmony-ec
COMMON=/app/firmware/common

if [ ! -d "$WOLFSSL" ]; then
    echo "wolfSSL tree not mounted at $WOLFSSL - aborting." >&2
    exit 2
fi
if [ ! -d "$HARMONY_CRYPTO" ]; then
    echo "Harmony crypto driver missing at $HARMONY_CRYPTO - aborting." >&2
    exit 2
fi

rm -rf "$WOLFSSL_SRC"
cp -a "$WOLFSSL" "$WOLFSSL_SRC"

mkdir -p "$HARMONY_BUILD"
HARMONY_OBJS=()
for src in \
    src/MCHP_Crypto_Hash_HwSha.c \
    src/MCHP_Crypto_Sym_HwAes.c \
    src/MCHP_Crypto_Rng_HwTrng.c \
    src/MCHP_Crypto_Hmac_HwSha.c \
    ; do
    if [ -f "$HARMONY_CRYPTO/$src" ]; then
        out="$HARMONY_BUILD/$(basename ${src%.c}).o"
        mipsel-linux-gnu-gcc \
            -EL -mips32r2 -G0 -ffreestanding -fno-pic -mno-abicalls \
            -fno-common -fno-builtin -O2 \
            -D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x43 \
            -I"$HARMONY_CRYPTO" -I"$HARMONY_CRYPTO/src" \
            -I"$COMMON" \
            -include "$COMMON/pic32mz_stubs.h" \
            -c -o "$out" "$HARMONY_CRYPTO/$src"
        HARMONY_OBJS+=("$out")
    fi
done

if [ ${#HARMONY_OBJS[@]} -gt 0 ]; then
    mipsel-linux-gnu-ar rcs "$HARMONY_BUILD/libcrypto-harmony.a" "${HARMONY_OBJS[@]}"
else
    echo "WARN: no Harmony source files matched; producing empty archive." >&2
    : > /tmp/empty.c
    mipsel-linux-gnu-gcc -c /tmp/empty.c -o /tmp/empty.o
    mipsel-linux-gnu-ar rcs "$HARMONY_BUILD/libcrypto-harmony.a" /tmp/empty.o
fi

mkdir -p "$WOLFSSL_BUILD"
/app/scripts/build-wolfssl-static.sh "$WOLFSSL_SRC" "$WOLFSSL_BUILD" \
    "-D__PIC32_FEATURE_SET0=0x45 -D__PIC32_FEATURE_SET1=0x43 \
     -DWOLFSSL_PIC32MZSIM_HARMONY \
     -include $COMMON/user_settings.h \
     -include $COMMON/pic32mz_stubs.h \
     -I$COMMON -isystem $COMMON/xc-include \
     -I$HARMONY_CRYPTO -I$HARMONY_CRYPTO/src"

make -C "$FW" \
    WOLFSSL_DIR="$WOLFSSL_SRC" \
    WOLFSSL_LIB="$WOLFSSL_BUILD/libwolfssl.a" \
    HARMONY_DIR="$HARMONY_CRYPTO" \
    HARMONY_LIB="$HARMONY_BUILD/libcrypto-harmony.a"

exec /usr/local/bin/pic32mz-sim \
    --chip pic32mz2048ech144 \
    --timeout 600 \
    --exit-on test_complete \
    --result-symbol test_result \
    "$FW/wolfcrypt.elf"
