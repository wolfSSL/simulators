# TROPIC01Sim hardware validation

The simulator's default personality (`es-0.1.2`) was checked against a real
TROPIC01 with a conformance probe that runs, unchanged, on the chip and on
the simulator. This file describes the bench, the probe, what it found and
what is still unverified.

## Bench

- **Host:** wolfDemo board (STM32U585, 160 MHz) with the TROPIC01 on a
  mikroBUS board, connected over SPI1. libtropic 4.2.0 with its
  `stm32u5xx` HAL and the wolfCrypt CAL.
- **Chip:** engineering sample, application firmware 0.1.2, SPECT firmware
  0.3.1, bootloader 1.0.1. Pairing slot 0 holds libtropic's engineering
  sample key, slots 1 to 3 are empty. The R-Config is erased except
  `CFG_START_UP` (`0xffffffef`); the I-Config is fully erased.
  R-Memory slots hold 444 bytes.

## The probe

[`conformance/tr01_conf.c`](conformance/tr01_conf.c) drives the chip
through libtropic and, where libtropic would hide the chip's answer,
through hand-built L2 frames and L3 commands. Every observation is one
line:

- `T <id> ...` must be identical on the chip and on the simulator (L2
  status bytes, CHIP_STATUS, response lengths, L3 result codes, libtropic
  return codes, signature checks, the shape of L1 transactions);
- `I <id> ...` is informational and differs per device (firmware versions,
  configuration values, random data, keys).

The sections are:

| Section | Covers |
| --- | --- |
| A | L2 without a session: GET_INFO objects and certificate blocks, malformed requests, unknown request IDs, CRC errors, RESEND, SLEEP, GET_LOG, STARTUP, L1 polling traces |
| B | Secure session: handshake with good, wrong and empty pairing keys, abort, tag errors, partial L3 chunks, sessions across SLEEP |
| C | Every L3 command: PING sizes, unknown command IDs, RANDOM, pairing key reads, R-/I-Config reads, ECC generate/store/read/erase/sign on both curves (RFC 6979 and RFC 8032 keys, invalid scalars, wrong curves, out of range slots, bad command sizes), R-Memory, monotonic counters, MAC-and-Destroy |
| D | Reboot into application and maintenance (start-up) mode, what the bootloader answers, firmware bank headers |

The probe only makes reversible changes: it uses ECC slots 29 to 31,
R-Memory slots 509 to 511, counter 15 and MAC-and-Destroy slots 126 and
127 as scratch space and erases or re-initializes them. It never writes
pairing keys, the R-Config or the I-Config (the only pairing key
invalidation it sends names slot 4, which does not exist and is refused).

The chip's output is in
[`conformance/baseline/hw-es-0.1.2.txt`](conformance/baseline/hw-es-0.1.2.txt)
(device-unique values removed). The simulator now matches all 267 `T`
lines.

### Running it against the simulator

```bash
cargo build --release --manifest-path tropic01-sim/Cargo.toml --bin tcp_server
make -C conformance LIBTROPIC_DIR=/path/to/libtropic WOLFSSL_DIR=/path/to/wolfssl
conformance/run.sh
```

`run.sh` starts a freshly provisioned simulator, runs the probe and diffs
its `T` lines with the baseline. `Dockerfile.conformance` does the same in
a container and runs in CI (`tropic01-conformance.yml`), so any change
that moves the simulator away from the recorded hardware behaviour fails
the build.

### Running it on a chip

Build `tr01_conf.c` for the MCU with a platform file that provides
`plat_setup_handle()` (fills in the libtropic HAL device and CAL context)
and `plat_delay_ms()`, and calls `tr01_conf_run()`. Compile the libtropic
HAL with its SPI functions renamed to `*_real` (see the `lt_hal.o` rule in
`conformance/Makefile`) so the probe can trace L1 traffic. Capture the
UART output and compare the `T` lines with `run.sh`'s third argument.

Do **not** build the probe with `-DCONF_ALARM_TEST` for a real chip unless
you can cut its power completely: those requests put the chip into ALARM
mode (see below).

## What the chip does

These are the behaviours the probe recorded that host code, and the
simulator, have to get right. Codes are L2 status bytes (`REQUEST_OK 01`,
`REQUEST_CONT 03`, `RESP_DISABLED 78`, `HSK_ERR 79`, `NO_SESSION 7A`,
`CRC_ERR 7C`, `UNKNOWN_ERR 7E`, `GEN_ERR 7F`) and L3 result bytes (`OK c3`,
`FAIL 3c`, `UNAUTHORIZED 01`, `INVALID_CMD 02`, `SLOT_NOT_EMPTY 10`,
`INVALID_KEY 12`, `UPDATE_ERR 13`, `SLOT_EMPTY 15`).

### L1 and L2

- Every SPI transaction starts with CHIP_STATUS. While the chip works on a
  request it answers GET_RESPONSE polls with READY cleared; libtropic
  reports `LT_L1_CHIP_BUSY` for a poll with nothing pending. A response is
  served once; after it has been clocked out completely, only RESEND brings
  it back (repeatedly, byte for byte).
- An unknown request ID, including the firmware update requests in
  application mode, is `UNKNOWN_ERR`. A known request with a wrong length
  or a bad argument (GET_INFO object, certificate block 30 or higher,
  STARTUP ID, SLEEP kind, RESEND with data) is `GEN_ERR`. A bad CRC is
  `CRC_ERR`, and RESEND after a CRC error repeats `CRC_ERR`.
- The certificate store spans 30 blocks of 128 bytes. FW_BANK headers are
  only available in maintenance mode (20-byte headers on bootloader 1.0.1).
- GET_LOG returns a 252-byte chunk on this engineering sample.
- SLEEP with kind 5 is accepted and ends the secure session.
- Encrypted commands without a session are `NO_SESSION`; SESSION_ABORT is
  accepted with or without a session.
- A handshake naming an empty pairing slot is `HSK_ERR`.
- An L3 packet longer than one 252-byte L2 chunk is acknowledged with
  `REQUEST_CONT` until the last chunk. A packet whose AES-GCM tag fails is
  acknowledged with `REQUEST_OK`, then the chip drops the session: the
  next command gets `NO_SESSION`.
- In maintenance mode CHIP_STATUS is `0x05`, only GET_INFO, RESEND, GET_LOG
  and STARTUP are served (everything else is `UNKNOWN_ERR`), and GET_INFO
  reports the bootloader version with bit 7 of the major byte set.

### L3

- Unknown command IDs are `INVALID_CMD`, including `0xa0` to `0xa5`, which
  earlier versions of the simulator used for a simulated on-chip AES.
- PING echoes 0 to 4096 bytes.
- RANDOM_VALUE_GET returns 0 to 255 bytes after 3 padding bytes. A longer
  command is executed anyway; a shorter one is `FAIL`.
- Out of range slots and indexes (pairing slot 4, ECC slot 32, R-Memory
  slot 512, counter 16, MAC-and-Destroy slot 128, configuration addresses
  beyond the map) are `UNAUTHORIZED`; misaligned configuration addresses
  are `FAIL`.
- ECC: reading or signing with an empty slot is `INVALID_KEY`, erasing an
  empty slot is `OK`, generating or storing into an occupied slot is
  `FAIL`, using a key with the other curve's sign command is
  `INVALID_KEY`. Storing a P-256 scalar of 0, n or 2^256 - 1 is `FAIL`; an
  all-zero Ed25519 seed is accepted. ECDSA signatures are randomized (not
  RFC 6979) and so are Ed25519 signatures, yet both verify against the
  standard algorithms.
- Firmware 0.1.2 is lenient about L3 sizes: ECDSA_Sign, EDDSA_Sign and
  MAC_And_Destroy commands of the wrong size answer `OK` with no data, an
  EdDSA signature of an empty message is `OK` with no data, and other
  commands of the wrong size are `FAIL`.
- R-Memory: slots hold 1 to 444 bytes; 0 or more than 444 bytes is
  `FAIL`. Writing an occupied slot is `SLOT_NOT_EMPTY`; reading an empty
  slot is `OK` with no data (libtropic turns that into
  `LT_L3_R_MEM_DATA_READ_SLOT_EMPTY`).
- Monotonic counters count down. An update at 0 is `UPDATE_ERR` and leaves
  the counter at 0; the largest initial value is `0xfffffffe`.
- MAC-and-Destroy outputs depend on the slot and on the sequence of inputs,
  as the KMAC-based construction in Tropic Square's documentation
  describes.
- A reboot ends the session; a reboot into maintenance mode and back
  restores normal operation.

### ALARM mode

A handshake that names a pairing slot above 3 puts firmware 0.1.2 into
ALARM mode (CHIP_STATUS ALARM bit set, every request refused). Only a full
power cycle clears it. On the bench that meant powering off both the board
and the J-Link, because the J-Link powers the board through SWD. The
simulator models this (`TROPIC01_SIM_PERSONALITY=es-0.1.2`); a TCP
`POWER_OFF`/`POWER_ON` or `RESET_TARGET` clears it. Firmware 2.x answers
`HSK_ERR` instead, according to Tropic Square's model.

## Not verified on hardware

- **The `2.2.0` personality.** It follows Tropic Square's functional model
  (ts-tvl) and release notes: strict L3 sizes (a wrong size is an L2
  `GEN_ERR` and closes the session), 475-byte R-Memory slots, 52-byte
  firmware bank headers, an empty log, the `prod0` pairing key.
- **Irreversible operations.** Pairing key writes and invalidations,
  R-Config writes and erases, and I-Config writes follow the datasheet and
  the model. The probe does not perform them on a chip.
- **User Access Privileges.** The bench chip's configuration grants
  everything to every pairing slot, so UAP enforcement (the R-Config AND
  I-Config value, one bit per pairing slot) is modelled from the
  documentation.
- **Timing.** The simulator answers after `TROPIC01_SIM_BUSY_POLLS` busy
  polls (default 1); it does not model how long the chip takes.
- **Certificates.** The simulator generates a chain with the same structure
  as the chip's (X25519 device certificate, P-384 intermediate, P-384
  cross certificate and P-521 root) under its own root, so it does not
  validate against Tropic Square's roots.
- **Firmware update** is not implemented.
