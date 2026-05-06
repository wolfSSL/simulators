/* user_settings.h - wolfSSL/wolfCrypt configuration for STM32H753
 * under stm32-sim.
 *
 * Originally derived from wolfssl/.github/renode-test/stm32h753/
 * user_settings.h. The conservative Renode settings (NO_STM32_HASH,
 * NO_AES_CBC, AES-GCM only via HAL_CRYP) are preserved here for CI
 * stability. stm32-sim is *capable* of HASH and the full AES mode
 * set, but the HAL_HASH/HAL_CRYP register-sequence interactions
 * still need debugging before we can safely flip them on. See
 * docs/wolfssl-broader-coverage.diff for the trial config that
 * broadens coverage once those issues are resolved.
 */

#ifndef USER_SETTINGS_STM32SIM_H
#define USER_SETTINGS_STM32SIM_H

/* -------------------------  Platform  ------------------------------------- */
#define WOLFSSL_ARM_CORTEX_M
#define WOLFSSL_STM32H7
#define WOLFSSL_STM32_CUBEMX

/* Required for consistent math library settings (CTC_SETTINGS) */
#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8

/* -------------------------  Threading / OS  ------------------------------- */
#define SINGLE_THREADED

/* -------------------------  Filesystem / I/O  ----------------------------- */
#define WOLFSSL_NO_CURRDIR
#define NO_FILESYSTEM
#define NO_WRITEV

/* -------------------------  wolfCrypt Only  ------------------------------- */
#define WOLFCRYPT_ONLY
#define NO_DH
#define NO_DSA
#define NO_DES
#define NO_DES3

/* -------------------------  RNG Configuration  ---------------------------- */
#define WOLFSSL_STM32_RNG_NOLIB
#define NO_DEV_RANDOM
#define HAVE_HASHDRBG

/* -------------------------  Math Library  --------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define SP_WORD_SIZE 32

/* -------------------------  Crypto Hardening  ----------------------------- */
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT

/* -------------------------  Size Optimization  ---------------------------- */
#define WOLFSSL_SMALL_STACK

/* -------------------------  Test Configuration  --------------------------- */
#define BENCH_EMBEDDED
#define NO_MAIN_DRIVER

#endif /* USER_SETTINGS_STM32SIM_H */
