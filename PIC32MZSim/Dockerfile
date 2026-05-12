# Dockerfile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of PIC32MZSim.
#
# PIC32MZSim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Builds the PIC32MZ simulator + the bare-metal smoke firmware for
# both EC and EF, then runs the Cargo test suite. The cargo tests
# exercise the CE/RNG peripherals at the BD/SA byte level and via
# small hand-written MIPS sequences.

# ---- Stage 1: build newlib-nano for mipsel-unknown-elf ----
# Debian does not ship a bare-metal MIPS newlib (only ARM). Build it
# once from upstream source against our mipsel-linux-gnu cross-gcc; the
# resulting libc.a / libm.a are link-compatible with our firmware's
# `-fno-pic -mno-abicalls -ffreestanding` ABI.
FROM debian:bookworm AS newlib-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc-mipsel-linux-gnu binutils-mipsel-linux-gnu \
        wget xz-utils texinfo ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG NEWLIB_VERSION=4.4.0.20231231
RUN wget -q https://sourceware.org/pub/newlib/newlib-${NEWLIB_VERSION}.tar.gz && \
    tar xf newlib-${NEWLIB_VERSION}.tar.gz && \
    rm newlib-${NEWLIB_VERSION}.tar.gz

RUN mkdir /build && cd /build && \
    /newlib-${NEWLIB_VERSION}/configure \
        --target=mipsel-unknown-elf \
        --prefix=/opt/newlib-mipsel \
        --disable-multilib \
        --disable-libgloss \
        --disable-newlib-supplied-syscalls \
        --enable-newlib-nano-formatted-io \
        --enable-newlib-nano-malloc \
        --enable-newlib-reent-small \
        --disable-newlib-fvwrite-in-streamio \
        --disable-newlib-fseek-optimization \
        --disable-newlib-wide-orient \
        --disable-newlib-unbuf-stream-opt \
        --enable-target-optspace \
        CC_FOR_TARGET=mipsel-linux-gnu-gcc \
        AR_FOR_TARGET=mipsel-linux-gnu-ar \
        AS_FOR_TARGET=mipsel-linux-gnu-as \
        LD_FOR_TARGET=mipsel-linux-gnu-ld \
        RANLIB_FOR_TARGET=mipsel-linux-gnu-ranlib \
        CFLAGS_FOR_TARGET="-EL -mips32r2 -G0 -mno-gpopt -ffreestanding -fno-pic -mno-abicalls -fno-common -O2 -g" && \
    make -j$(nproc) && \
    make install

# ---- Stage 2: simulator workspace + smoke firmware ----
FROM rust:1.85-bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc-mipsel-linux-gnu \
        binutils-mipsel-linux-gnu \
        cmake \
        pkg-config \
        clang \
        libclang-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=newlib-builder /opt/newlib-mipsel /opt/newlib-mipsel

WORKDIR /app

COPY pic32mz-sim/ /app/pic32mz-sim/
COPY firmware/   /app/firmware/

RUN cd /app/pic32mz-sim && cargo build --release 2>&1

RUN make -C /app/firmware/smoke-test-ec
RUN make -C /app/firmware/smoke-test-ef

CMD ["cargo", "test", "--manifest-path", "/app/pic32mz-sim/Cargo.toml", "--release", "--", "--test-threads=1", "--nocapture"]
