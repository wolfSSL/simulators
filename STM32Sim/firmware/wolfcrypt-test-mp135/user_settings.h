/* user_settings.h - wolfSSL/wolfCrypt configuration for STM32MP135
 * under stm32-sim. The MP135 is a Cortex-A7 (ARMv7-A), not a
 * Cortex-M, so we drop WOLFSSL_ARM_CORTEX_M and the M-asm flag.
 *
 * wolfSSL 5.8.4+ knows WOLFSSL_STM32MP13 natively: it aliases
 *   CRYP   -> CRYP1
 *   RNG    -> RNG1
 *   __HAL_RCC_HASH_CLK_ENABLE -> __HAL_RCC_HASH1_CLK_ENABLE
 *   __HAL_RCC_RNG_CLK_ENABLE  -> __HAL_RCC_RNG1_CLK_ENABLE
 * and selects STM32_HAL_V2 for the v2 crypto HAL flavour.
 */

#ifndef USER_SETTINGS_STM32SIM_MP135_H
#define USER_SETTINGS_STM32SIM_MP135_H

/* The MP13 HAL headers use uint32_t but don't include <stdint.h>
 * themselves. wolfSSL pulls in stm32mp13xx_hal.h from settings.h
 * before its own stdint-using headers, so the integer types must be
 * available beforehand. */
#include <stdint.h>
#include <stddef.h>

#define WOLFSSL_STM32MP13
#define WOLFSSL_STM32_CUBEMX
#define STM32_HAL_V2
#define WOLFSSL_STM32_PKA

#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8

#define SINGLE_THREADED

#define WOLFSSL_NO_CURRDIR
#define NO_FILESYSTEM
#define NO_WRITEV

#define WOLFCRYPT_ONLY
#define NO_DH
#define NO_DSA
#define NO_DES
#define NO_DES3

/* RNG via HAL */
#define WOLFSSL_STM32_RNG_NOLIB
#define NO_DEV_RANDOM
#define HAVE_HASHDRBG

/* Math: single-precision software paths for everything not on PKA.
 * No M-asm here, this is an A-class target. */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define SP_WORD_SIZE 32

#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT
#define WOLFSSL_SMALL_STACK
#define BENCH_EMBEDDED
#define NO_MAIN_DRIVER

/* The MP135 HASH peripheral implements SHA3, SHAKE, and the
 * SHA-384/512 family in hardware. The simulator's HASH1 model
 * decodes ALGO codes 4-11 as SHA3-{224,256,384,512} / SHAKE-{128,256}
 * (RAWSHAKE collapses to SHAKE).
 *
 * SHAKE is currently disabled because wolfSSL master's
 * wolfcrypt/src/sha3.c has a bug in the STM32_HASH_SHA3 branch:
 * wc_Shake128_Update() / wc_Shake128_Final() call the in-file static
 * helpers `Sha3Update` / `Sha3Final` / `InitSha3` (no `wc_` prefix),
 * but those helpers are gated by
 *   #if !defined(STM32_HASH_SHA3) && !defined(PSOC6_HASH_SHA3)
 * (sha3.c line 588) so they don't exist in our build. The build dies
 * with implicit-declaration errors on Sha3Update / Sha3Final /
 * InitSha3. Until that wolfSSL bug is fixed, we keep SHAKE off here;
 * the simulator's HASH1 model still services SHAKE-128 / SHAKE-256
 * for firmware that drives the peripheral directly (e.g. the
 * smoke-test KATs). SHA3 itself works through the wc_Sha3_*
 * entry points and stays enabled. */
#define WOLFSSL_SHA3
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#endif /* USER_SETTINGS_STM32SIM_MP135_H */
