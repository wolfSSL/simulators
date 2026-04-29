FROM rust:1.85-bookworm

WORKDIR /app

COPY atecc608-sim/ /app/atecc608-sim/

RUN cd /app/atecc608-sim && cargo build 2>&1

CMD ["cargo", "test", "--manifest-path", "/app/atecc608-sim/Cargo.toml", "--", "--test-threads=1", "--nocapture"]
