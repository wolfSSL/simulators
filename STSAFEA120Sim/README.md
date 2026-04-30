# STSAFE-A120 Simulator

A software simulator for the STMicroelectronics STSAFE-A120 secure element, written in Rust. Implements the STSAFE-A wire protocol over TCP and the wolfSSL-required subset of the STSAFE command surface, so wolfSSL + STSELib can be regression-tested without physical hardware.

## Features

### Cryptographic operations
- **ECDSA**: NIST P-256 key generation, sign, verify
- **ECDH**: NIST P-256 shared secret (Establish Key)
- **RNG**: 1..255 random bytes per request, drawn from `rand::OsRng`
- **Echo**: byte-for-byte loopback (for sanity / smoke tests)

### Device state
- 8-byte serial number (returned by `Query(PRODUCT_DATA)`)
- ECC private-key slots, sparse map keyed by slot number
- Slot 0 pre-provisioned with a P-256 device key
- Slot 0xFF reserved for ephemeral ECDHE keys
- Data zones (sparse map keyed by zone index)
- Zone 0 pre-provisioned with a minimal DER-shaped device certificate
- JSON-persisted object store

### Protocol
- STSAFE-A wire framing with CRC-16/X-25 (poly 0x1021 reflected, init 0xFFFF, refin/refout/xorout)
- Command (host -> device): `[cmd_header 1B][params][crc16 2B BE]`
- Response (device -> host): `[rsp_header 1B][length 2B BE][body][crc16 2B BE]`
- Supported opcodes (v1): Echo (0x00), Generate Random (0x02), Read (0x05), Hibernate (0x0D), Generate Key (0x11), Query (0x14), Generate Signature (0x16), Verify Signature (0x17), Establish Key (0x18), Standby (0x19), Reset (0x01)
- TCP transport (port 8120 by default)

## Quick start

All three Docker tiers are run from inside `STSAFEA120Sim/`:

```bash
# 1. Rust unit + integration tests (CRC, framing, dispatch, TCP end-to-end)
docker build -t stsafe-a120-sim .
docker run --rm stsafe-a120-sim

# 2. STSELib + OpenSSL cross-verification (high-level stse_* API)
docker build -f Dockerfile.sdk-test -t stsafe-a120-sdk-test .
docker run --rm stsafe-a120-sdk-test

# 3. wolfSSL + STSELib -- wolfCrypt API tests against the simulator
docker build -f Dockerfile.wolfcrypt -t stsafe-a120-wolfcrypt .
docker run --rm stsafe-a120-wolfcrypt
```

## Native development

```bash
# Build
cargo build --manifest-path stsafe-a120-sim/Cargo.toml

# Unit + integration tests
cargo test --manifest-path stsafe-a120-sim/Cargo.toml -- --test-threads=1

# Run the TCP server (listens on 127.0.0.1:8120)
cargo run --manifest-path stsafe-a120-sim/Cargo.toml --release --bin tcp_server
```

Environment variables for the TCP server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `STSAFE_SIM_BIND` | `127.0.0.1` | Listen address |
| `STSAFE_SIM_PORT` | `8120` | Listen port |
| `STSAFE_SIM_STORE` | `stsafe_a120_store.json` | On-disk persistence path |
| `STSAFE_SIM_FRESH` | (unset) | If set, ignore the on-disk store and reprovision |

## Not implemented

- **Host sessions / encrypted commands.** The simulator runs in plain mode only -- no AES-CBC C-MAC (host MAC) and no AES-CBC payload encryption. wolfSSL's STSAFE-A120 path does not exercise these.
- **Extended commands** (cmd_header == 0x1F): KEK sessions, hash, decompress public key, etc. They return `STSE_COMMAND_CODE_NOT_SUPPORTED`. wolfSSL's A120 integration uses Generate Key (slot 0xFF) for ephemeral ECDHE rather than the extended Generate ECDHE command, so this is sufficient for current coverage.
- **Curves other than NIST P-256.** Brainpool, P-384/P-521, Curve25519, Ed25519 are deliberately omitted to keep the handler set narrow.
- **A100 / A110.** Out of scope -- those variants need ST's proprietary middleware which isn't publicly distributable.

## License

GPL-3.0-or-later. See `LICENSE`.
