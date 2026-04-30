# Dockerfile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of STSAFEA120Sim.
#
# STSAFEA120Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Rust unit + TCP integration tests.
FROM rust:1.85-bookworm

WORKDIR /app

COPY stsafe-a120-sim/ /app/stsafe-a120-sim/

RUN cd /app/stsafe-a120-sim && cargo build 2>&1

CMD ["cargo", "test", "--manifest-path", "/app/stsafe-a120-sim/Cargo.toml", "--", "--test-threads=1", "--nocapture"]
