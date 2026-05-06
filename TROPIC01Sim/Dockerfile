# Dockerfile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of TROPIC01Sim.
#
# TROPIC01Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Rust unit + TCP integration tests.
FROM rust:1.85-bookworm

WORKDIR /app

COPY tropic01-sim/ /app/tropic01-sim/

RUN cd /app/tropic01-sim && cargo build 2>&1

CMD ["cargo", "test", "--manifest-path", "/app/tropic01-sim/Cargo.toml", "--", "--test-threads=1", "--nocapture"]
