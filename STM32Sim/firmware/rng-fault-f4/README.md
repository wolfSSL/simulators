# rng-fault-f4

STM32F4 hardware-RNG fault test for wolfSSL's `wc_GenerateSeed()`.

The firmware pulls a short seed with the RNG healthy, then a long one while
the RNG fails part way through. A correct `wc_GenerateSeed()` returns from
the second call, with `0` if the RNG recovered or `RNG_FAILURE_E` (-199) if
it did not. The regression it guards against is the call never returning:
before the fix, the Standard Peripheral Library arm of the `STM32_RNG` seed
code polled DRDY with no bound, so a seed or clock error mid-request hung
it forever with the crypto hardware mutex held.

Two `wc_GenerateSeed()` arms can be built:

| `ARM=`      | wolfSSL configuration |
|-------------|-----------------------|
| `stdperiph` | `WOLFSSL_STM32F4`, neither `WOLFSSL_STM32_CUBEMX` nor `WOLFSSL_STM32_BARE` (the Standard Peripheral Library arm) |
| `nolib`     | `WOLFSSL_STM32_RNG_NOLIB` (direct register access) |

ST's Standard Peripheral Library is not vendored. `stdperiph/` holds a
StdPeriph-style `stm32f4xx.h` wrapper and `stdperiph_shim.c` implements the
handful of RNG/RCC calls the seed code makes, with the same register-level
behaviour as the library's functions of the same names.

## On stm32-sim (CI)

```sh
make TARGET=sim ARM=stdperiph WOLFSSL_ROOT=/path/to/wolfssl
stm32-sim --chip stm32f417 --timeout 20 --rng-fault seed:200 \
    rng-fault-stdperiph-sim.elf
```

The simulator's `--rng-fault` option supplies the fault.
`scripts/run-rng-fault-f417.sh` builds both arms and runs every fault
scenario with its expected result; a hang fails with the PC it hung at.

## On an STM32F4DISCOVERY (STM32F407)

```sh
make TARGET=board ARM=stdperiph WOLFSSL_ROOT=/path/to/wolfssl
./board-run.sh rng-fault-stdperiph-board.elf 8
```

`board-run.sh` programs the board with OpenOCD over the on-board ST-LINK,
lets it run, halts it and prints the test's state, the RNG and RCC
registers, and the function the PC is in.

The board build stops the RNG kernel clock itself: SYSCLK stays on the
16 MHz HSI and the main PLL runs only to feed the 48 MHz PLL48CLK, so a
SysTick interrupt can switch the PLL off 3 ms into the long seed request
without stopping the core. The silicon reports a genuine clock error
(RNG_SR = 0x22, CECS | CEIS) and DRDY stops. `GLITCH_MS=<n>` switches
the PLL back on n ms later instead, for a transient glitch.

What to look for:

| Variable        | Meaning |
|-----------------|---------|
| `g_stage`       | 2 = still inside the faulted `wc_GenerateSeed()`, 3 = it returned |
| `g_fault_ret`   | its return value (stays 1 if it never returned) |
| `g_hung`        | set by SysTick if it has not returned 5 s after the fault |
| `g_rng_sr_after_fault` | RNG_SR 100 ms after the fault |
| `g_return_tick` | SysTick ms at which it returned (fault at `g_fault_fired_tick`) |

LEDs: green = sanity seed passed, orange = faulted call returned,
red = faulted call hung, blue = heartbeat.

Make variables `CMSIS_CORE` and `CMSIS_DEVICE` point at the ARM CMSIS
core headers and ST's `cmsis-device-f4` headers (default: the `/opt`
layout of the Docker image).
