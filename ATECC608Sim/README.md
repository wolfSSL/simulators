# ATECC608A Simulator

A software simulator for the Microchip ATECC608A secure element, written in
Rust. Implements the ATCA wire protocol over TCP and the wolfSSL-required
subset of the ATECC command surface, so wolfSSL + cryptoauthlib can be
regression-tested without physical hardware.

## Features

### Cryptographic operations
- **ECDSA**: P-256 key generation, sign, verify (external-pubkey mode)
- **ECDH**: P-256 shared secret (clear output)
- **SHA-256**: one-shot and multi-step (Start / Update / End)
- **RNG**: 32-byte cryptographic random

### Device state
- 128-byte Config zone with wolfSSL-friendly defaults (SN populated, 8 ECC
  private-key slots, 8 data slots, both zones ship locked but per-slot
  unlocked so GenKey still works)
- 64-byte OTP zone
- 16 data slots × 72 bytes
- Lock state machine for Config zone, Data+OTP zone, and per-slot
- JSON-persisted object store

### Protocol
- ATCA wire framing with CRC-16 (poly 0x8005, init 0, non-reflected)
- Command packets: `[count][opcode][p1][p2][data][crc]`
- Supported opcodes in v1: Info (0x30), Random (0x1B), Nonce (0x16),
  GenKey (0x40), Sign (0x41), Verify (0x45), ECDH (0x43), SHA (0x47),
  Read (0x02), Write (0x12), Lock (0x17)
- TCP transport (port 8608 by default)

## Quick start

All three Docker tiers are run from inside `ATECC608Sim/`:

```bash
# 1. Rust unit + integration tests (CRC, framing, dispatch, TCP end-to-end)
docker build -t atecc608-sim .
docker run atecc608-sim

# 2. cryptoauthlib + OpenSSL cross-verification (atcab_* API)
docker build -f Dockerfile.sdk-test -t atecc608-sdk-test .
docker run atecc608-sdk-test

# 3. wolfSSL + cryptoauthlib — wolfCrypt API tests against the simulator
docker build -f Dockerfile.wolfcrypt -t atecc608-wolfcrypt .
docker run atecc608-wolfcrypt
```

## Architecture

```
┌─────────────────────────────────────┐
│  Test binary or wolfSSL+cryptoauthlib│
└────────────┬────────────────────────┘
             │  TCP socket on port 8608
┌────────────▼────────────────────────┐
│  sdk-test/hal_tcp.c                 │
│  custom cryptoauthlib HAL           │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  atecc608-sim/src/bin/tcp_server.rs │
│  multi-threaded TCP listener        │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  atca.rs : framing + CRC            │
│  dispatch.rs : opcode routing       │
│  handlers/*.rs : per-opcode logic   │
│  session.rs : per-conn TempKey+SHA  │
│  object_store : JSON-persisted      │
│                 Config/OTP/Slots    │
└─────────────────────────────────────┘
```

### Transport model

- TCP connection itself represents "awake" — the word-address byte `0x00`
  (wake pulse) is silent on the wire. Emitting the datasheet's 4-byte
  wake response would leave stale bytes in the socket buffer that
  cryptoauthlib's next command-response read would mis-parse. This matches
  how cryptoauthlib's Linux I2C HAL actually drives the device at the
  protocol boundary — wake is a signalling event, not a bytestream
  exchange.
- `0x01` (sleep) wipes per-session volatile state (TempKey + SHA context).
- `0x02` (idle) preserves volatile state — cryptoauthlib interleaves idle
  between sub-commands of a multi-step SHA or Nonce+Sign sequence and
  relies on TempKey/SHA surviving.

### Object store

`Arc<Mutex<Store>>` shared across all TCP connections, file-backed as
`atecc608_store.json`. TempKey and SHA context are **per-session** (per
connection), matching real silicon volatile RAM. Set `ATECC608_SIM_FRESH=1`
on the server to discard the on-disk store and provision from defaults.

## Integration notes

### wolfSSL + cryptoauthlib — single-pass build

Unlike SE050Sim, there is no circular dependency between wolfSSL and
cryptoauthlib. `Dockerfile.wolfcrypt` builds:

1. cryptoauthlib with `ATCA_HAL_CUSTOM=ON`, no built-in HALs (our test
   binary links in `hal_tcp.c` directly).
2. wolfSSL `master` with `--with-cryptoauthlib=/usr`,
   `-DWOLFSSL_ATECC608A`, and `-DWOLFSSL_ATECC_NO_ECDH_ENC` (the default
   encrypted-ECDH path still calls a 5-arg `atcab_ecdh_enc` signature
   that newer cryptoauthlib renamed; the plain path works fine).
3. `--enable-fastmath` is required -- the default sp-math backend returns
   `MP_VAL` on the `mp_read_unsigned_bin(key->pubkey.x, ...)` call inside
   wolfSSL's ATECC keygen path.

### ECDH in the wolfCrypt tier

wolfSSL's atmel slot allocator reserves a single slot
(`ATECC_SLOT_ECDHE_PRIV`) for `wc_ecc_make_key_ex` calls, so we can only
make one hardware ECDH key per process. The sdk-test tier exercises
`atcab_ecdh` end-to-end (both sides on the simulator), which is the
functional proof; the wolfCrypt tier runs RNG + SHA-256 + ECDSA
sign/verify.

## Known limitations

- No SCP / I/O protection. All commands are unencrypted on the wire
  (matching how cryptoauthlib's Linux I2C HAL talks to the chip).
- Only P-256 is supported for ECC operations (matching real ATECC608A).
- The simulator does not model the on-chip counter increment / use-limit
  policies — counters are accepted but not rate-limited.
- The sdk-test tier covers the full `atcab_*` surface we use; the
  wolfCrypt tier is a smoke test limited to keygen-by-one-slot
  operations.

## License

GPL-3.0-or-later. See [../LICENSE](../LICENSE) at the repo root.
