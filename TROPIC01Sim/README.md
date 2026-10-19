# TROPIC01 Simulator

A software simulator for the Tropic Square TROPIC01 secure element, written
in Rust. It speaks libtropic's "TROPIC01 model" protocol over TCP (the
`hal/posix/tcp` HAL), emulates the chip's SPI side byte for byte, runs the
Noise_KK1_25519_AESGCM_SHA256 secure channel and implements the full
application firmware L3 command set. Host code built on libtropic (wolfSSL's
TROPIC01 port, the wolfHSM TROPIC01 port, applications) can be tested
without hardware.

The default personality was validated against a real chip: a conformance
probe that runs unchanged on the chip and on the simulator produces 267
identical behavioural observations. See
[HARDWARE_VALIDATION.md](HARDWARE_VALIDATION.md) for the bench, the probe,
the chip behaviours it recorded and what is not verified.

## Firmware personalities

TROPIC01 behaviour differs between firmware releases. Select one with
`TROPIC01_SIM_PERSONALITY`:

| Personality | Models | Validated |
| --- | --- | --- |
| `es-0.1.2` (default) | Engineering sample: application FW 0.1.2, SPECT FW 0.3.1, bootloader 1.0.1, 444-byte R-Memory slots, lenient L3 size checks, debug log enabled, libtropic's `eng_sample` key in pairing slot 0 | Against a real chip |
| `2.2.0` | Production part: application FW 2.2.0, SPECT FW 1.3.0, bootloader 2.0.1, 475-byte R-Memory slots, strict L3 sizes (L2 `GEN_ERR` and session close), empty log, libtropic's `prod0` key in pairing slot 0 | Against Tropic Square's functional model (ts-tvl) and release notes |

## What is simulated

### L1 (SPI)

- CHIP_STATUS on every transaction (READY, ALARM and START_UP bits), the
  `0xAA` GET_RESPONSE poll and a configurable number of busy polls before
  a response is ready.
- Responses are served once and only RESEND repeats them. Encrypted L3
  results longer than one 252-byte L2 chunk are returned as `RESULT_CONT`
  chunks, and L3 commands are reassembled from `REQUEST_CONT` chunks.
- TCP `POWER_ON`, `POWER_OFF` and `RESET_TARGET` power cycle the chip: the
  session, queued responses and ALARM mode are lost, persistent state is
  kept.

### L2

- `GET_INFO`: certificate store (30 blocks of 128 bytes), CHIP_ID, RISC-V
  and SPECT firmware versions, firmware bank headers (maintenance mode
  only).
- `HANDSHAKE`, `ENCRYPTED_CMD`, `ENCRYPTED_SESSION_ABT`, `RESEND`, `SLEEP`,
  `GET_LOG`, `STARTUP` (reboot into application or maintenance mode).
- The chip's status codes for malformed, unknown and out of mode requests,
  bad CRCs and failed AES-GCM tags (which drop the session).

### L3

| ID | Command |
| --- | --- |
| `0x01` | PING (up to 4096 bytes) |
| `0x10` - `0x12` | PAIRING_KEY_WRITE / READ / INVALIDATE (4 slots) |
| `0x20` - `0x22` | R_CONFIG_WRITE / READ / ERASE |
| `0x30`, `0x31` | I_CONFIG_WRITE (clears one bit) / READ |
| `0x40` - `0x42` | R_MEM_DATA_WRITE / READ / ERASE (512 slots) |
| `0x50` | RANDOM_VALUE_GET (0 to 255 bytes) |
| `0x60` - `0x63` | ECC_KEY_GENERATE / STORE / READ / ERASE (32 slots, P-256 and Ed25519) |
| `0x70` | ECDSA_SIGN (P-256 over a 32-byte hash, randomized) |
| `0x71` | EDDSA_SIGN (Ed25519, 1 to 4096 byte messages) |
| `0x80` - `0x82` | MCOUNTER_INIT / UPDATE / GET (16 counters, counting down) |
| `0x90` | MAC_AND_DESTROY (128 slots, KMAC256 construction) |

Every command is gated by its User Access Privilege configuration (the
R-Config AND I-Config value, one bit per pairing slot), and result codes
follow the chip: `UNAUTHORIZED` for out of range targets, `INVALID_KEY` for
empty ECC slots, `SLOT_NOT_EMPTY`, `SLOT_EMPTY`, `UPDATE_ERR` and so on.
Unknown command IDs are `INVALID_CMD`.

### Device state

Each simulated device is provisioned on first start (or with
`TROPIC01_SIM_FRESH=1`) and saved as JSON after every SPI transfer:

- a CHIP_ID with the personality's layout and a random serial number;
- a static X25519 key pair (STPRIV/STPUB) and a four-certificate store with
  the same structure as the chip's: the X25519 device certificate, a P-384
  intermediate, a P-384 cross certificate and a P-521 root, all issued
  under the simulator's own root CA (they do not chain to Tropic Square's
  roots);
- pairing slot 0 with the personality's libtropic key, slots 1 to 3 empty;
- for `es-0.1.2` the R-Config read from the bench chip (`CFG_START_UP`
  0xffffffef, the rest erased), for `2.2.0` an erased R-Config; an erased
  I-Config;
- empty ECC slots, R-Memory, counters and MAC-and-Destroy slots.

With `TROPIC01_SIM_WOLFSSL_FIXTURES=1`, R-Memory slots 0 to 3 are filled
with the AES key, IV and Ed25519 key pair that wolfSSL's TROPIC01 port
(`wolfcrypt/src/port/tropicsquare/tropic01.c`) reads from its fixed slot
map. A real chip ships with empty R-Memory.

## Quick start

All tiers run from inside `TROPIC01Sim/`:

```bash
# 1. Rust unit and TCP integration tests
docker build -t tropic01-sim .
docker run --rm tropic01-sim

# 2. libtropic 4.2.0 (mbedTLS v4 CAL, posix/tcp HAL) driving the simulator
docker build -f Dockerfile.sdk-test -t tropic01-sdk-test .
docker run --rm tropic01-sdk-test

# 3. wolfSSL --with-tropic01 and Tropic Square's wolfssl-test app
docker build -f Dockerfile.wolfcrypt -t tropic01-wolfcrypt .
docker run --rm tropic01-wolfcrypt

# 4. Conformance probe against the simulator, compared with the hardware baseline
docker build -f Dockerfile.conformance -t tropic01-conformance .
docker run --rm tropic01-conformance
```

## Native development

```bash
# Build
cargo build --manifest-path tropic01-sim/Cargo.toml --release

# Unit and integration tests
cargo test --manifest-path tropic01-sim/Cargo.toml -- --test-threads=1

# Run the TCP server (127.0.0.1:28992, libtropic's posix/tcp default)
cargo run --manifest-path tropic01-sim/Cargo.toml --release --bin tcp_server

# Conformance check (needs libtropic and wolfSSL checkouts)
make -C conformance LIBTROPIC_DIR=/path/to/libtropic WOLFSSL_DIR=/path/to/wolfssl
conformance/run.sh
```

Environment variables of the TCP server:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TROPIC01_SIM_BIND` | `127.0.0.1` | Listen address |
| `TROPIC01_SIM_PORT` | `28992` | Listen port |
| `TROPIC01_SIM_STORE` | `tropic01_store.json` | Persistent device state |
| `TROPIC01_SIM_FRESH` | unset | Provision a new device, ignoring the stored one |
| `TROPIC01_SIM_PERSONALITY` | `es-0.1.2` | Firmware personality (`es-0.1.2`, `2.2.0`); a stored device keeps its personality unless `TROPIC01_SIM_FRESH` is set |
| `TROPIC01_SIM_WOLFSSL_FIXTURES` | unset | Pre-load wolfSSL's R-Memory fixtures at provisioning |
| `TROPIC01_SIM_BUSY_POLLS` | `1` | GET_RESPONSE polls answered "busy" before each response |

## Pinned upstream versions

| Tier | Dependency | Pin | Why |
| --- | --- | --- | --- |
| 2 (sdk-test) | libtropic | v4.2.0 (`9085ea5`) | Current API, and the release the hardware was validated with |
| 2 | mbedTLS | 4.0.0 | What libtropic's examples fetch for the PSA CAL; OpenSSL verifies Ed25519 because that mbedTLS profile lacks PureEdDSA |
| 3 (wolfcrypt) | libtropic | v0.1.0 | wolfSSL's TROPIC01 port uses the v0.x API (`lt_random_get`, `verify_chip_and_start_secure_session`, ...) |
| 3 | wolfSSL | `master` | Tracks the port; the build fixes a `ForceZero` / `wc_ForceZero` typo in `tropic01.c` |
| 3 | tropic01-wolfssl-test | `main` | Tropic Square's test app, with its USB dongle HAL swapped for TCP |
| 4 (conformance) | libtropic | v4.2.0 (`9085ea5`) | The baseline was recorded with it |
| 4 | wolfSSL | v5.9.4-stable | wolfCrypt CAL and signature checks |

## Not implemented

- Firmware update: the firmware update L2 requests are `UNKNOWN_ERR` in
  both modes (on the chip that is only true in application mode).
- Chip timing: responses are ready after `TROPIC01_SIM_BUSY_POLLS` polls.
- Sensors, the GPO pin and physical attack detection.

## License

GPL-3.0-or-later. See [../LICENSE](../LICENSE) at the repo root.
