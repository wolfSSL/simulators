# PIC32MZSim

A simulator for the Microchip PIC32MZ EC and EF microcontrollers,
focused on exercising the on-chip Crypto Engine (CE) and RNG that
wolfSSL uses through its PIC32 hardware-crypto port. The goal is to
run the full `wolfcrypt_test` suite end-to-end in CI without real
silicon and without the Microchip XC32 toolchain (which is not freely
redistributable in public Docker images).

## Why not just use real hardware or QEMU?

- **No QEMU machine** for PIC32MZ exists upstream. A 2017 microaptiv
  patch series for the CPU never landed the SoC peripherals.
- **Hobby emulators** like `sergev/pic32sim` target PIC32MX and do not
  model the MZ Crypto Engine block at all.
- **Renode** has a MIPS core but no PIC32MZ platform definition.
- **Real silicon CI** would need the XC32 toolchain (proprietary EULA)
  and physical board farms.

PIC32MZSim closes that gap with a Rust simulator that drives Unicorn
Engine for MIPS32 CPU emulation and registers our own peripheral
models for the Crypto Engine, RNG, and UART.

## Architecture

Cargo workspace under [`pic32mz-sim/`](pic32mz-sim):

```
pic32mz-sim/
  core/          CPU + MMIO bus + ELF loader + Runner (MIPS32LE)
  peripherals/   CE (BD+SA parser, AES/SHA/3DES executor), RNG, UART
  chips/         pic32mz2048ech144 / pic32mz2048efh144 (memory map + wiring)
  runner-bin/    `pic32mz-sim` CLI binary
```

The chip configurations are tiny — both EC and EF share the same
memory map and peripheral wiring; the only behavioural difference is
that the EC chip config flips a `no_out_swap` flag on the CE
peripheral so `CECON.OUT_SWAP` (bit 7) is ignored, matching the
`PIC32_NO_OUT_SWAP` quirk in `wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h`.

Peripheral state is purely volatile - no JSON persistence layer. Each
run constructs a fresh `Cpu`, loads the ELF, runs to completion, and
drops everything.

## Status

Both **PIC32MZ EC** (no FPU, no hardware out-swap) and **PIC32MZ EF**
(FPU + out-swap) chip targets boot, run firmware, and drive their
on-chip cryptographic peripherals end-to-end:

| Peripheral | EC | EF |
|------------|------|------|
| UART2      | OK   | OK   |
| RNG        | LFSR seed-from-CP0 | TRNG + LFSR |
| CE / AES   | ECB/CBC/CTR/GCM | ECB/CBC/CTR/GCM |
| CE / DES + 3DES | ECB/CBC | ECB/CBC |
| CE / Hash  | MD5/SHA-1/SHA-256 | MD5/SHA-1/SHA-256 |
| CE / HMAC  | streaming-hash path | streaming-hash path |

## Building

The Rust workspace builds with stable Rust >= 1.74:

```sh
cd pic32mz-sim
cargo build --release
```

Firmware images are C and need a MIPS cross toolchain
(`gcc-mipsel-linux-gnu` on Debian/Ubuntu):

```sh
make -C firmware/smoke-test-ec
make -C firmware/smoke-test-ef
```

## Running

```sh
./pic32mz-sim/target/release/pic32mz-sim \
  --chip pic32mz2048efh144 \
  --timeout 30 \
  --exit-on test_complete \
  --result-symbol test_result \
  firmware/smoke-test-ef/smoke.elf
```

Expected output ends with `=== smoke test passed ===` and the binary
exits 0 when the firmware sets `test_result = 0` and `test_complete = 1`.

## Docker tiers

```sh
# Tier 1: cargo test + smoke firmware
docker build -t pic32mz-sim PIC32MZSim
docker run pic32mz-sim

# Tier 2/3: wolfCrypt test through the direct-register port
docker build -f PIC32MZSim/Dockerfile.wolfcrypt-direct -t pic32mz-wolfcrypt-direct PIC32MZSim
docker run -v $(realpath ../wolfssl):/opt/wolfssl:ro pic32mz-wolfcrypt-direct \
    /app/scripts/run-wolfcrypt-direct-ef.sh
docker run -v $(realpath ../wolfssl):/opt/wolfssl:ro pic32mz-wolfcrypt-direct \
    /app/scripts/run-wolfcrypt-direct-ec.sh

# Tier 2/3 alt: wolfCrypt through the MPLAB Harmony 3 crypto driver
docker build -f PIC32MZSim/Dockerfile.wolfcrypt-harmony -t pic32mz-wolfcrypt-harmony PIC32MZSim
docker run -v $(realpath ../wolfssl):/opt/wolfssl:ro pic32mz-wolfcrypt-harmony \
    /app/scripts/run-wolfcrypt-harmony-ef.sh
docker run -v $(realpath ../wolfssl):/opt/wolfssl:ro pic32mz-wolfcrypt-harmony \
    /app/scripts/run-wolfcrypt-harmony-ec.sh
```

All five jobs are mirrored as GitHub Actions workflows in
[`.github/workflows/pic32mz-*.yml`](../.github/workflows/).

## Environment variables

- `PIC32MZ_SIM_TRACE_MMIO=1` - dump every MMIO read/write to stderr.
- `PIC32MZ_SIM_TRACE_BD=1` - dump each Crypto Engine BD + SA in hex
  before executing. Useful when chasing bit-pattern mismatches with
  the wolfSSL driver - the single biggest source of subtle bugs when
  the simulator and `pic32mz-crypt.c` disagree on the SA/BD field
  layout in `wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h`.

## Not implemented (deliberately)

- **microMIPS / MIPS16e encodings** - we build all firmware as plain
  MIPS32 to sidestep Unicorn's incomplete decoder for those forms.
- **DSP ASE r2 / FPU** - the wolfSSL PIC32 port is integer-only.
- **Cache modelling** - the linker script puts everything in KSEG1
  (uncached). The wolfSSL port already tags its streaming-hash global
  with `__attribute__((coherent))` to force KSEG1, so this is a
  strict superset behaviourally.
- **EJTAG / ICD probe emulation**.
- **PIC32MZ DA** (multimedia variant) - same CE block but the 2D GPU
  is out of scope.
- **XC32 toolchain support** - public CI uses gcc-mipsel-linux-gnu
  + a thin SFR stub header (`firmware/common/pic32mz_stubs.h`).

## License

GPL-3.0-or-later. See [../LICENSE](../LICENSE) at the repo root.
