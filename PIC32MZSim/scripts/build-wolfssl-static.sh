#!/bin/bash
# Copyright (C) 2026 wolfSSL Inc.
#
# Compile wolfcrypt sources into a static library for the PIC32MZ
# wolfcrypt-test firmware. Bypasses autoconf entirely - autoconf's
# "C compiler can produce executables" probe always fails when we
# pass the bare-metal CFLAGS the firmware needs (-ffreestanding,
# -fno-pic, -mno-abicalls) because the Debian mipsel-linux-gnu
# toolchain only ships a hard-float Linux libc that those flags
# cannot link against. Direct compile sidesteps the probe and matches
# what wolfSSL's `mplabx/wolfssl.X` project does for real silicon.
#
# Arguments:
#   $1  WOLFSSL_SRC    wolfSSL source tree (already copied to a
#                      writable scratch dir).
#   $2  OUT_DIR        Output directory; the library is written to
#                      ${OUT_DIR}/libwolfssl.a, objects to ${OUT_DIR}/obj/.
#   $3  EXTRA_CFLAGS   Variant-specific CFLAGS (feature set, harmony vs
#                      direct, include paths). Quoted as one argument.

set -eu

WOLFSSL_SRC=$1
OUT_DIR=$2
EXTRA_CFLAGS=$3

OBJ_DIR="$OUT_DIR/obj"
mkdir -p "$OBJ_DIR"

NEWLIB_DIR=${NEWLIB_DIR:-/opt/newlib-mipsel/mipsel-unknown-elf}

# Common bare-metal CFLAGS. Match what the firmware Makefiles use so
# the resulting libwolfssl.a is link-compatible with the firmware ELF.
# `-isystem $NEWLIB_DIR/include` keeps wolfSSL's <stdlib.h> / <string.h>
# / <time.h> includes resolving to newlib's bare-metal headers instead
# of the host's glibc.
BASE_CFLAGS="-EL -mips32r2 -G0 -mno-gpopt -ffreestanding -fno-pic -mno-abicalls \
             -fno-common -fno-builtin -ffunction-sections -fdata-sections \
             -O2 \
             -Wno-error -Wno-unused-parameter -Wno-implicit-function-declaration \
             -Wno-nested-externs -Wno-unused-function -Wno-unused-variable \
             -isystem $NEWLIB_DIR/include \
             -U__unix__ -U__linux__ \
             -DWOLFSSL_USER_SETTINGS"

# Files in wolfcrypt/src/ that we do not want in libwolfssl.a: just
# the benchmark binary entry point.
EXCLUDES_REGEX='(benchmark\.c)$'

SRCS=$(find "$WOLFSSL_SRC/wolfcrypt/src" -maxdepth 1 -name '*.c' \
        | grep -Ev "$EXCLUDES_REGEX")

# Pull in the PIC32 hardware-crypto port (defines wc_Sha256Pic32Free,
# wc_Pic32HashCopy, etc. that the sha/sha256/aes sources reference
# when WOLFSSL_MICROCHIP_PIC32MZ is set).
if [ -f "$WOLFSSL_SRC/wolfcrypt/src/port/pic32/pic32mz-crypt.c" ]; then
    SRCS="$SRCS
$WOLFSSL_SRC/wolfcrypt/src/port/pic32/pic32mz-crypt.c"
fi

# Pull in wolfcrypt/test/test.c so the firmware can call wolfcrypt_test()
# (wolfSSL's full self-test driver). Each variant's main.c is now a thin
# trampoline that runs wolfcrypt_test(NULL) - this exercises ASN.1,
# Base64, Memory, MD5 (incl. LARGE_HASH polling), SHA-1, SHA-256, RANDOM,
# HMAC-{MD5,SHA,SHA256}, GMAC, AES (ECB / CBC / CTR / 192 / 256), AES-GCM,
# logging, mutex, memcb - the entire surface the PIC32 port plus the
# wolfssl C-side wrapper cover.
if [ -f "$WOLFSSL_SRC/wolfcrypt/test/test.c" ]; then
    SRCS="$SRCS
$WOLFSSL_SRC/wolfcrypt/test/test.c"
fi

# --- wolfSSL PIC32 port fix: wc_Pic32HashFree XFREE's the wrong pointer ----
#
# In wolfcrypt/src/port/pic32/pic32mz-crypt.c, wc_Pic32HashUpdate may set
# `cache->buf = stdBuf` (a pointer to the wc_Md5/Sha/Sha256 struct's
# embedded `buffer` array, which is typically on the caller's stack) when
# the incoming data fits in the standard buffer. If the caller subsequently
# calls wc_Md5Free / wc_ShaFree / wc_Sha256Free without first calling
# Final (e.g. wolfcrypt_test's md5_test exit path after the LARGE_HASH +
# Copy cleanup sub-tests), wc_Pic32HashFree ends up calling
# `XFREE(cache->buf, ...)` on a stack pointer, which corrupts newlib's
# nano-malloc free list and later faults a future malloc with READ_UNALIGNED.
#
# Fix by passing the stdBuf pointer into wc_Pic32HashFree so it can skip
# the XFREE when cache->buf is the stack-backed standard buffer.
PIC32_CRYPT_C="$WOLFSSL_SRC/wolfcrypt/src/port/pic32/pic32mz-crypt.c"
if [ -f "$PIC32_CRYPT_C" ]; then
    sed -i \
        -e 's|^static void wc_Pic32HashFree(hashUpdCache\* cache, void\* heap)$|static void wc_Pic32HashFree(hashUpdCache* cache, void* stdBuf, void* heap)|' \
        -e 's|^    if (cache \&\& cache->buf \&\& !cache->isCopy) {$|    if (cache \&\& cache->buf \&\& cache->buf != stdBuf \&\& !cache->isCopy) {|' \
        -e 's|wc_Pic32HashFree(\&md5->cache, md5->heap);|wc_Pic32HashFree(\&md5->cache, (byte*)md5->buffer, md5->heap);|' \
        -e 's|wc_Pic32HashFree(\&sha->cache, sha->heap);|wc_Pic32HashFree(\&sha->cache, (byte*)sha->buffer, sha->heap);|' \
        -e 's|wc_Pic32HashFree(\&sha256->cache, sha256->heap);|wc_Pic32HashFree(\&sha256->cache, (byte*)sha256->buffer, sha256->heap);|' \
        "$PIC32_CRYPT_C"
fi

echo ">> Building libwolfssl.a from $(echo "$SRCS" | wc -l) source files"

for src in $SRCS; do
    obj="$OBJ_DIR/$(basename "${src%.c}").o"
    mipsel-linux-gnu-gcc \
        $BASE_CFLAGS $EXTRA_CFLAGS \
        -I"$WOLFSSL_SRC" \
        -c -o "$obj" "$src"
done

mipsel-linux-gnu-ar rcs "$OUT_DIR/libwolfssl.a" "$OBJ_DIR"/*.o
echo ">> Built $OUT_DIR/libwolfssl.a ($(stat -c%s "$OUT_DIR/libwolfssl.a") bytes)"
