/* user_settings.h - wolfSSL/wolfCrypt configuration for STM32U585
 * under stm32-sim.
 *
 * Modeled on the H7 wolfcrypt-test-h7/user_settings.h with the
 * adjustments STM32U585 needs:
 *   - WOLFSSL_STM32U5 selects the U5 register layout in the
 *     wolfssl/wolfcrypt/src/port/st/stm32.c port code
 *   - STM32_HAL_V2 picks the v2 HAL flavour (different CRYP /
 *     HASH register adapters compared to H7)
 *   - WOLFSSL_STM32_PKA enables the PKA-accelerated ECC / RSA
 *     paths in wolfSSL
 *   - STM32_HASH and STM32_CRYPTO are *enabled* (the simulator
 *     models AES + HASH for U5 just like for H7)
 */

#ifndef USER_SETTINGS_STM32SIM_U5_H
#define USER_SETTINGS_STM32SIM_U5_H

#define WOLFSSL_ARM_CORTEX_M
#define WOLFSSL_STM32U5
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

/* Math */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define SP_WORD_SIZE 32

#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT
#define WOLFSSL_SMALL_STACK
#define BENCH_EMBEDDED
#define NO_MAIN_DRIVER

#endif /* USER_SETTINGS_STM32SIM_U5_H */
