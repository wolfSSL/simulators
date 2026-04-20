FROM rust:1.85-bookworm

WORKDIR /app

# Clone the nxp-se050 driver (sim-compat branch carries the fixes that used to
# live in patches/apply.sh)
RUN git clone --branch sim-compat --depth 1 \
    https://github.com/LinuxJedi/nxp-se050.git /app/nxp-se050

# Copy simulator source
COPY se050-sim/ /app/se050-sim/

# Build the simulator
RUN cd /app/se050-sim && cargo build 2>&1

# Run all tests (unit + integration) by default
CMD ["cargo", "test", "--manifest-path", "/app/se050-sim/Cargo.toml", "--", "--nocapture", "--test-threads=1"]
