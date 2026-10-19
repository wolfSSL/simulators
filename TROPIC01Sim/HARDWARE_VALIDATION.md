# TROPIC01Sim hardware validation

Two of the simulator's personalities were checked against one real TROPIC01
with a conformance probe that runs, unchanged, on the chip and on the
simulator: `es-0.1.2` against the chip as shipped, and `es-2.2.0` against
the same chip after a firmware update. This file describes the bench, the
probe, what it found and what is still unverified.

## Bench

- **Host:** wolfDemo board (STM32U585, 160 MHz) with the TROPIC01 on a
  mikroBUS board, connected over SPI1. libtropic 4.2.0 with its
  `stm32u5xx` HAL and the wolfCrypt CAL.
- **Chip:** engineering sample (P/N TR01-B2S-T005, ABAB silicon),
  bootloader 1.0.1. Pairing slot 0 holds libtropic's engineering sample
  key, slots 1 to 3 are empty.
  - **As shipped** (`es-0.1.2`): application firmware 0.1.2, SPECT
    firmware 0.3.1. The R-Config is erased except `CFG_START_UP`
    (`0xffffffef`); the I-Config is fully erased. R-Memory slots hold 444
    bytes.
  - **Updated** (`es-2.2.0`): application firmware 2.2.0, SPECT firmware
    1.3.0, written with libtropic v4.2.0's `lt_do_mutable_fw_update` and
    its `boot_v_1_0_1/fw_v_2_2_0` images (built with
    `LT_SILICON_REV_ABAB`). The update writes both firmware bank pairs; it
    cannot be undone. Then the fix for erratum OI_TR01_ERR_2026090100 (see
    below) cleared `RNGTEST_DIS` (bit 2 of `CFG_START_UP`): R-Config
    `0xffffffeb`, I-Config `0xfffffffb`. R-Memory slots hold 475 bytes.

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

Two checks only run on application firmware 2.x: a handshake naming
pairing slot 4 (A14), which puts firmware 0.1.2 into ALARM mode, and the
SPECT size error checks (C10), which need firmware 2.x's strict sizes.
The firmware 0.1.2 baseline predates them, and that chip cannot go back to
0.1.2. Before A12 the probe aborts any session a previous program left
open, and before the MAC-and-Destroy checks (C09) it puts the slot into a
known state, so a run does not depend on what ran on the chip before.

The probe only makes reversible changes: it uses ECC slots 29 to 31,
R-Memory slots 509 to 511, counter 15 and MAC-and-Destroy slots 126 and
127 as scratch space and erases or re-initializes them. It never writes
pairing keys, the R-Config or the I-Config (the only pairing key
invalidation it sends names slot 4, which does not exist and is refused).
The erratum fix was a separate, one-off program.

The chip's output is in
[`conformance/baseline/hw-es-0.1.2.txt`](conformance/baseline/hw-es-0.1.2.txt)
and
[`conformance/baseline/hw-es-2.2.0.txt`](conformance/baseline/hw-es-2.2.0.txt)
(device-unique values removed; two runs of the firmware 2.2.0 probe on the
chip gave identical `T` lines). The simulator matches all 267 and all 357
`T` lines.

### Running it against the simulator

```bash
cargo build --release --manifest-path tropic01-sim/Cargo.toml --bin tcp_server
make -C conformance LIBTROPIC_DIR=/path/to/libtropic WOLFSSL_DIR=/path/to/wolfssl
conformance/run.sh
```

For each `baseline/hw-<personality>.txt`, `run.sh` starts a freshly
provisioned simulator with that personality, runs the probe and diffs its
`T` lines with the baseline. `Dockerfile.conformance` does the same in a
container and runs in CI (`tropic01-conformance.yml`), so any change that
moves the simulator away from the recorded hardware behaviour fails the
build.

### Running it on a chip

Build `tr01_conf.c` for the MCU with a platform file that provides
`plat_setup_handle()` (fills in the libtropic HAL device and CAL context)
and `plat_delay_ms()`, and calls `tr01_conf_run()`. Compile the libtropic
HAL with its SPI functions renamed to `*_real` (see the `lt_hal.o` rule in
`conformance/Makefile`) so the probe can trace L1 traffic. Capture the
UART output and compare its `T` lines with the baseline for the chip's
firmware (`run.sh SIM_BIN PROBE_BIN BASELINE` checks one baseline).

Do **not** build the probe with `-DCONF_ALARM_TEST` for a real chip unless
you can cut its power completely: those requests put the chip into ALARM
mode (see below).

## What the chip does

These are the behaviours the probe recorded that host code, and the
simulator, have to get right. Unless a section says otherwise they hold for
both firmware versions. Codes are L2 status bytes (`REQUEST_OK 01`,
`REQUEST_CONT 03`, `RESP_DISABLED 78`, `HSK_ERR 79`, `NO_SESSION 7A`,
`CRC_ERR 7C`, `UNKNOWN_ERR 7E`, `GEN_ERR 7F`) and L3 result bytes (`OK c3`,
`FAIL 3c`, `UNAUTHORIZED 01`, `INVALID_CMD 02`, `SLOT_NOT_EMPTY 10`,
`INVALID_KEY 12`, `UPDATE_ERR 13`, `SLOT_EMPTY 15`).

### L1 and L2

- Every SPI transaction starts with CHIP_STATUS. While the chip works on a
  request, firmware 0.1.2 and the bootloader answer GET_RESPONSE polls
  with READY cleared, while firmware 2.2.0 keeps READY set and answers
  STATUS `NO_RESP` (`0xff`), as when nothing is pending; libtropic polls
  again either way, and reports `LT_L1_CHIP_BUSY` for a poll with nothing
  pending. A response is
  served once; after it has been clocked out completely, only RESEND brings
  it back (repeatedly, byte for byte).
- An unknown request ID, including the firmware update requests in
  application mode, is `UNKNOWN_ERR`. A known request with a wrong length
  or a bad argument (GET_INFO object, certificate block 30 or higher,
  STARTUP ID, SLEEP kind, RESEND with data) is `GEN_ERR`. A bad CRC is
  `CRC_ERR`, and RESEND after a CRC error repeats `CRC_ERR`.
- The certificate store spans 30 blocks of 128 bytes. FW_BANK headers are
  only available in maintenance mode (20-byte headers on bootloader 1.0.1).
  After the update both bank pairs hold the new images.
- GET_LOG returns a 252-byte chunk on this engineering sample, with either
  firmware.
- SLEEP with kind 5 is accepted and ends the secure session.
- Encrypted commands without a session are `NO_SESSION`; SESSION_ABORT is
  accepted with or without a session.
- A handshake naming an empty pairing slot is `HSK_ERR`; on firmware
  2.2.0 so is one naming slot 4 (firmware 0.1.2 goes into ALARM mode).
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
- R-Memory: slots hold 1 to 444 bytes on firmware 0.1.2 and 1 to 475
  bytes on firmware 2.2.0; 0 or more is `FAIL`. Writing an occupied slot is `SLOT_NOT_EMPTY`; reading an empty
  slot is `OK` with no data (libtropic turns that into
  `LT_L3_R_MEM_DATA_READ_SLOT_EMPTY`).
- Monotonic counters count down. An update at 0 is `UPDATE_ERR` and leaves
  the counter at 0; the largest initial value is `0xfffffffe`.
- MAC-and-Destroy outputs depend on the slot and on the sequence of inputs,
  as the KMAC-based construction in Tropic Square's documentation
  describes.
- A reboot ends the session; a reboot into maintenance mode and back
  restores normal operation.

### Firmware 2.2.0

- An L3 command whose size does not fit its command ID is acknowledged
  with `REQUEST_OK`, answered with `GEN_ERR`, and the session is closed.
  This applies to every command; firmware 0.1.2's lenient answers are
  gone. An EdDSA signature of an empty message is a normal signature.
- A **SPECT command** (ECC_Key_Generate, _Store, _Read, _Erase, ECDSA_Sign,
  EDDSA_Sign, MAC_And_Destroy) rejected for its size leaves the firmware
  in a bad state. The same mistake with a command the CPU handles (PING,
  RANDOM, R-Memory, counters, configuration, pairing keys) does not. The
  state survives the session closing, SESSION_ABORT and new handshakes; a
  reboot clears it. It ends with the next well-formed command:
  - a SPECT command executes normally;
  - an unknown command ID is `INVALID_CMD` as usual;
  - any other command is **not executed** and answers result `0x00` with
    zeroed fields: PING keeps its length (and echoes zeros), RANDOM returns
    a length that changes from run to run, the other commands answer the
    result byte alone. libtropic reports `LT_L3_RESULT_UNKNOWN`. An
    R-Memory write or a counter update sent then is lost.

  Host code built on libtropic never sends a wrong size, so this only
  matters for hand-built commands. The simulator models it (`L3State` in
  `handlers/l3.rs`) with a one-byte answer for RANDOM.

### Erratum OI_TR01_ERR_2026090100

On early engineering samples the `RNGTEST_DIS` bit (bit 2 of
`CFG_START_UP`) was left at 1 in both configurations, so the firmware never
initialises the physical TRNG. Firmware 0.1.2 runs anyway. On firmware
2.2.0 the first RANDOM_VALUE_GET puts the chip into ALARM mode, and the
firmware log (streamed on MISO in ALARM mode) shows the error. Tropic
Square's fix clears the bit in the R-Config (erase it first, then write the
whole configuration back, or the chip can be left in ALARM mode for good:
erratum OI_TR01_ERR_2026010800) and in the I-Config; keys and secrets the
chip generated before the fix should be regenerated. After the fix the bench chip answers RANDOM normally, also
after a power cycle. The simulator does not model the erratum: its RNG
always works.

### ALARM mode

A handshake that names a pairing slot above 3 puts firmware 0.1.2 into
ALARM mode (CHIP_STATUS ALARM bit set, every request refused). Only a full
power cycle clears it. On the bench that meant powering off both the board
and the J-Link for at least 30 seconds, because the J-Link powers the
board through SWD. The simulator models this
(`TROPIC01_SIM_PERSONALITY=es-0.1.2`); a TCP `POWER_OFF`/`POWER_ON` or
`RESET_TARGET` clears it. Firmware 2.2.0 answers `HSK_ERR` instead.

## Not verified on hardware

- **Production parts (`2.2.0`).** Its firmware behaviour is the one
  recorded on the updated engineering sample (`es-2.2.0`). The part
  behaviour follows Tropic Square's functional model (ts-tvl) and
  libtropic's model configuration: bootloader 2.0.1 with 52-byte firmware
  bank headers, an empty log, the `prod0` pairing key, the CHIP_ID layout.
- **Corners of the SPECT size error.** Whether a wrong-size command sent
  while the state is set clears it, and whether SLEEP or a maintenance
  reboot clears it (the simulator assumes no, no and yes).
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
