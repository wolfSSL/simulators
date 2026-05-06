# TROPIC01 Simulator

A software simulator for the Tropic Square TROPIC01 secure element, written in Rust. Speaks libtropic's "TROPIC01 Model" wire protocol over TCP, performs the full Noise_KK1_25519_AESGCM_SHA256 secure-channel handshake, and answers the L3 command surface that libtropic and wolfSSL exercise -- so wolfSSL's TROPIC01 port can be regression-tested without physical hardware.

## Features

### Wire protocol layers
- **L1 SPI byte exchange** (the simulator emulates the chip's SPI side, including CHIP_STATUS polling and the `0xAA` GET_RESPONSE convention from `lt_l1.c`)
- **L2 frames**: `[REQ_ID(1B)][REQ_LEN(1B)][DATA][CRC(2B BE)]` with the libtropic-specific CRC-16 (poly `0x8005`, init `0x0000`, byte-swapped output) -- matches `lt_crc16.c` exactly
- **L3 secure channel**: full Noise_KK1 handshake (X25519 ECDH triple + custom HKDF chain + AES-GCM auth tag) and AES-256-GCM tunnel with per-direction nonce counters
- **TCP framing**: libtropic's `hal/posix/tcp/` `[tag(1B)][len(2B LE)][payload]` framing, matching `lt_posix_tcp_tag_t` exactly (`SPI_DRIVE_CSN_LOW/HIGH`, `SPI_SEND`, `WAIT`, `RESET_TARGET`, etc.)

### L3 commands
- `PING` (0x01) -- echo loopback
- `RANDOM_VALUE_GET` (0x50) -- 1..255 random bytes from `rand::OsRng`
- `ECC_KEY_GENERATE` / `STORE` / `READ` / `ERASE` (0x60-0x63) -- NIST P-256 + Ed25519
- `R_MEM_DATA_READ` / `WRITE` (0x40, 0x41) -- arbitrary host data slots
- `PAIRING_KEY_WRITE` / `READ` / `INVALIDATE` (0x10, 0x11, 0x12)

### L2 (plain) commands
- `GET_INFO` (0x01) -- chip ID, FW versions, X.509 certificate store (4-cert chunked read)
- `HANDSHAKE` (0x02) -- opens the Secure Channel
- `STARTUP` (0xB3), `SLEEP` (0x20), `SESSION_ABORT` (0x08), `RESEND` (0x10)

### Device state
- Random 12-byte chip ID (returned by `GET_INFO(CHIP_ID)`)
- Static X25519 keypair (STPRIV/STPUB) generated at first boot
- 4-cert "cert store" containing a DER device certificate carrying STPUB at the libtropic-recognisable X25519 SPKI offset
- Pairing slot 0 pre-provisioned with libtropic's `sh0pub_eng_sample` so the engineering-sample SHIPRIV/SHIPUB pair authenticates without extra setup
- R-memory slots 0-3 pre-provisioned to match the wolfSSL TROPIC01 port's hardcoded slot map (AES key, AES IV, Ed25519 pub, Ed25519 priv)
- JSON-persisted object store

## Quick start

All three Docker tiers are run from inside `TROPIC01Sim/`:

```bash
# 1. Rust unit + integration tests (CRC, framing, SPI emulator, handshake math, all L3 commands)
docker build -t tropic01-sim .
docker run --rm tropic01-sim

# 2. libtropic-driven SDK test (mbedTLS v4 CAL + posix/tcp HAL, exercises the same surface wolfSSL hits)
docker build -f Dockerfile.sdk-test -t tropic01-sdk-test .
docker run --rm tropic01-sdk-test

# 3. wolfSSL --with-tropic01 + Tropic Square's upstream wolfssl-test app (RNG, AES, Ed25519 keygen/sign/verify)
docker build -f Dockerfile.wolfcrypt -t tropic01-wolfcrypt .
docker run --rm tropic01-wolfcrypt
```

## Native development

```bash
# Build
cargo build --manifest-path tropic01-sim/Cargo.toml

# Unit + integration tests
cargo test --manifest-path tropic01-sim/Cargo.toml -- --test-threads=1

# Run the TCP server (listens on 127.0.0.1:28992 to match libtropic's posix/tcp HAL default)
cargo run --manifest-path tropic01-sim/Cargo.toml --release --bin tcp_server
```

Environment variables for the TCP server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TROPIC01_SIM_BIND` | `127.0.0.1` | Listen address |
| `TROPIC01_SIM_PORT` | `28992` | Listen port (matches `LIBTROPIC_PORT_POSIX_TCP`'s default) |
| `TROPIC01_SIM_STORE` | `tropic01_store.json` | On-disk persistence path |
| `TROPIC01_SIM_FRESH` | (unset) | If set, ignore the on-disk store and reprovision from defaults |

## Pinned upstream versions

| Tier | Dependency | Pin | Why |
| --- | --- | --- | --- |
| Tier 2 (sdk-test) | libtropic | commit `51044cd` | Latest libtropic master at the time of writing -- targets the modern `lt_*` API + posix/tcp HAL |
| Tier 2 | mbedTLS | `4.0.0` | Matches libtropic's hello_world example for the PSA crypto CAL |
| Tier 3 (wolfcrypt) | libtropic | `v0.1.0` | wolfSSL's port (`wolfcrypt/src/port/tropicsquare/tropic01.c`) calls `lt_random_get`, `verify_chip_and_start_secure_session`, `CURVE_ED25519`, and 4-arg `lt_r_mem_data_read` -- all renamed in libtropic v1.0.0. Pinning to v0.1.0 keeps the upstream port unchanged. |
| Tier 3 | wolfSSL | `master` | Tracks the latest port; the build sed-fixes a `ForceZero` -> `wc_ForceZero` typo in `tropic01.c`. |
| Tier 3 | tropic01-wolfssl-test | `main` | Tropic Square's upstream test app; the build sed-swaps its USB-dongle HAL for libtropic v0.1.0's `lt_port_unix_tcp.c`. |

## Not implemented

- **Application-FW commands beyond the wolfSSL surface.** Config-object read/write (R_CONFIG, I_CONFIG), MAC-and-Destroy, MCounter, monotonic counters, certificate-store mutation, and FW update commands are all stubbed -- they return `INVALID_CMD` (`0x02`) at the L3 layer.
- **Maintenance / startup mode.** The simulator always reports `LT_TR01_APPLICATION` mode. `lt_reboot(MAINTENANCE)` is acknowledged but does not change the chip's behaviour.
- **Alarm states.** The `TR01_L1_CHIP_MODE_ALARM_bit` is never set -- the chip stays in the "ready, application mode" state for the entire test run.
- **Real X.509 chain validation.** The device certificate in the cert store is a minimal DER blob carrying STPUB at the X25519 SPKI offset libtropic's parser looks for. It is *not* signed by a Tropic Square root and would fail real attestation. wolfSSL's smoke tests do not validate the cert chain.

## License

GPL-3.0-or-later. See `LICENSE`.
