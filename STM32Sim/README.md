# STM32Sim

A simulator for STMicroelectronics STM32 microcontrollers, focused on
exercising the on-chip cryptographic accelerators that wolfSSL uses
(CRYP/AES, HASH, RNG, PKA). It is designed to replace
[Renode](https://renode.io/) in the wolfSSL CI for STM32 targets and to
fill the gaps in Renode's hardware-crypto modeling.

## Why not just use Renode?

Today wolfSSL CI runs the wolfCrypt test suite against an
STM32H753-emulated-by-Renode board. Renode's STM32 model has known
gaps:

- The HASH peripheral is not modelled at all - hardware SHA/MD5/HMAC
  goes untested (`NO_STM32_HASH` is forced in the CI build).
- The CRYP peripheral only supports AES-GCM. CBC, ECB, CTR, CFB and
  OFB are disabled in the wolfSSL CI build because Renode does not
  implement them.
- The PKA (RSA/ECC accelerator) is not modelled.

STM32Sim aims to close those gaps and to add support for newer STM32
families (U5, H5, ...) that have peripheral revisions Renode does not
track on its own schedule.

## Architecture

We use [Unicorn Engine](https://www.unicorn-engine.org/) (QEMU-derived)
for ARM CPU emulation, and provide our own MMIO peripheral models in
Rust. The Cortex-M targets boot in Thumb/MCLASS mode; the MP135
target boots in ARM mode as a Cortex-A7 (with MMU). The repo is a
Cargo workspace under [`stm32-sim/`](stm32-sim):

```
stm32-sim/
  core/          CPU + MMIO bus + ELF loader + Runner
  peripherals/   USART, RCC, RNG, CRYP, HASH, PKA
  chips/         STM32H753 / STM32U575 / STM32U585 / STM32MP135 chip
                 configurations (memory map + peripheral wiring)
  runner-bin/    `stm32-sim` CLI binary
```

A `Chip` is the only thing that varies between targets: it's a list of
memory regions plus a bus with peripherals at their canonical base
addresses. Adding a new STM32 family is a new file under `chips/src/`.

Peripheral revisions (e.g. PKA v1 vs v2, CRYP HAL v1 vs v2) are
modelled by sharing the cryptographic core and varying only the
register-shape adapter, so SHA-256 logic is implemented exactly once
even though three chips might present three different DIN/HR layouts.

## Status

**STM32H753** (Cortex-M7, HAL v1, no PKA), **STM32U575/U585**
(Cortex-M33, HAL v2, PKA v2), and **STM32MP135** (Cortex-A7,
HAL v2 with the H7-style CRYP block, PKA v2) chip targets all boot,
run firmware, and drive their on-chip cryptographic peripherals end-
to-end:

| Peripheral | H7 (v1)                          | U5 (v2)            | MP135                                 |
|------------|----------------------------------|--------------------|---------------------------------------|
| USART      | OK                               | OK                 | OK (UART4)                            |
| RCC        | stub                             | stub               | stub                                  |
| RNG        | OK                               | OK                 | OK (RNG1)                             |
| CRYP/AES   | ECB/CBC/CTR/GCM (HAL-driven)     | ECB/CBC/CTR/GCM    | ECB/CBC/CTR/GCM (CRYP1, aliased CRYP) |
| HASH       | SHA-1/224/256, MD5               | SHA-1/224/256, MD5 | SHA-1/224/256, MD5, SHA-384/512, SHA3-224/256/384/512, SHAKE-128/256 (HASH1) |
| PKA        | n/a                              | ECC mul (P-256/P-384), RSA modexp, mod arithmetic | same as U5 |

The MP135 is bare-metal Cortex-A7 with no internal flash. The firmware
links at the DDR base (0xC0000000); the simulator maps DDR as plain
RAM and the ELF loader writes segments straight there, so no DDR_Init
helper is needed. The firmware enables a flat 1 MiB-section MMU map
during early boot to mirror the real-hardware path.

The peripheral register adapters are split into `v1.rs` (H7 / HAL v1)
and `v2.rs` (U5 / HAL v2) modules sharing the same cryptographic
engine in `mod.rs` - so adding e.g. STM32L5 PKA v1 in the future is a
new `v1.rs` adapter plus a chip file, no engine changes.

**Caveat for the PKA**: STM32 PKA reads operands from a vendor-internal
RAM layout encoded in HAL_PKA's offset tables (which live inside ST's
`stm32u5xx_hal_pka.c`). Until those offsets are transcribed in
`pka/v2.rs`, the adapter uses a synthetic operand layout for testing
purposes. Wiring PKA up to a real wolfSSL-on-STM32Cube run needs that
HAL register-trace work as a follow-up.

## Building

The Rust workspace builds with stable Rust >= 1.74:

```sh
cd stm32-sim
cargo build --release
```

The smoke-test firmwares are C and need an `arm-none-eabi-gcc`
toolchain:

```sh
make -C firmware/smoke-test-h7
make -C firmware/smoke-test-u5
make -C firmware/smoke-test-mp135
```

## Running

```sh
./stm32-sim/target/release/stm32-sim \
  --chip stm32h753 \
  --timeout 30 \
  --exit-on test_complete \
  --result-symbol test_result \
  firmware/smoke-test-h7/smoke.elf
```

Expected output ends with `=== smoke test passed ===` and the binary
exits 0 when the firmware sets `test_result = 0` and `test_complete = 1`.

## Tests

```sh
cargo test --manifest-path stm32-sim/Cargo.toml --release
```

This runs unit tests plus an end-to-end test that builds the smoke
firmware and runs it through the simulator binary. The integration
test is skipped if `arm-none-eabi-gcc` is not on `PATH`.

## Replacing wolfSSL's Renode CI

The wolfSSL repo currently runs the wolfCrypt test on STM32H753 under
Renode (`wolfssl/.github/workflows/renode-stm32h753.yml`). To swap
that for stm32-sim, on the wolfSSL side:

1. Drop in the workflow at
   [`docs/wolfssl-workflow-example.yml`](docs/wolfssl-workflow-example.yml)
   as `wolfssl/.github/workflows/stm32-sim-stm32h753.yml` and remove
   `renode-stm32h753.yml`.
2. The whole `wolfssl/.github/renode-test/stm32h753/` tree can also
   be removed - all of those firmware sources (main.c, startup,
   linker script, toolchain file, user_settings.h, HAL config) now
   live in this repo at
   [`firmware/wolfcrypt-test-h7/`](firmware/wolfcrypt-test-h7/), so
   wolfSSL no longer needs to carry them.

Once the HAL_HASH / HAL_CRYP non-GCM register-sequence bridge is
debugged in stm32-sim, applying
[`docs/wolfssl-broader-coverage.diff`](docs/wolfssl-broader-coverage.diff)
to `firmware/wolfcrypt-test-h7/` here broadens coverage to HASH (MD5 /
SHA-1 / SHA-224 / SHA-256) and the full AES mode set - the gaps
Renode left open. The peripheral models cover those cases standalone
(KAT-validated in
[`peripherals/src/{cryp,hash}/v1.rs::tests`](stm32-sim/peripherals/src)),
the open work is just the HAL bridge.

The local end-to-end test that validates the swap is
`docker build -f STM32Sim/Dockerfile.wolfcrypt STM32Sim` then
`docker run -v $WOLFSSL:/opt/wolfssl:ro stm32sim-wolfcrypt:ci`. With
a clean wolfSSL tree mounted, it produces
`=== wolfCrypt test passed! ===` in ~2 seconds.

## License

GPL-3.0-or-later. See [../LICENSE](../LICENSE) at the repo root.
