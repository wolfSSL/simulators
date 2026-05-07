# Dockerfile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of STM32Sim.
#
# STM32Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Builds the STM32 simulator and the smoke-test firmware, then runs the
# Cargo test suite (which includes an end-to-end test that boots the
# firmware on the simulator and asserts it reaches its pass marker).

FROM rust:1.85-bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc-arm-none-eabi \
        libnewlib-arm-none-eabi \
        cmake \
        pkg-config \
        clang \
        libclang-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY stm32-sim/ /app/stm32-sim/
COPY firmware/ /app/firmware/

RUN cd /app/stm32-sim && cargo build --release 2>&1
RUN make -C /app/firmware/smoke-test-h7
RUN make -C /app/firmware/smoke-test-u5

CMD ["cargo", "test", "--manifest-path", "/app/stm32-sim/Cargo.toml", "--release", "--", "--nocapture"]
