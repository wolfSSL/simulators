/* user_settings.h - wolfSSL/wolfCrypt configuration for STM32F417
 * running under stm32-sim.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STM32Sim.
 *
 * STM32Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STM32Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* The F417 crypto block: DES/TDES and AES ECB/CBC/CTR on the CRYP (no
 * GCM/CCM on this part), SHA-1 and MD5 on the HASH, and the RNG. SHA-2,
 * RSA and ECC run in software. */

#ifndef USER_SETTINGS_STM32SIM_F417_H
#define USER_SETTINGS_STM32SIM_F417_H

/* -------------------------  Platform  ------------------------------------- */
#define WOLFSSL_ARM_CORTEX_M
#define WOLFSSL_STM32F4
#define WOLFSSL_STM32_CUBEMX
/* Current STM32CubeF4 CRYP HAL only offers HAL_CRYP_Encrypt/Decrypt. */
#define STM32_HAL_V2

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

/* -------------------------  Symmetric  ------------------------------------ */
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
/* No GCM on the F417 CRYP: this covers wolfSSL's software GHASH fallback
 * (the model drops the GCM mode bits as the silicon does). */
#define HAVE_AESGCM
#define WOLFSSL_DES_ECB

/* -------------------------  RNG Configuration  ---------------------------- */
#define NO_DEV_RANDOM
#define HAVE_HASHDRBG

/* -------------------------  Math Library  --------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define SP_WORD_SIZE 32
#define HAVE_ECC

/* -------------------------  Crypto Hardening  ----------------------------- */
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT

/* -------------------------  Size Optimization  ---------------------------- */
#define WOLFSSL_SMALL_STACK

/* -------------------------  Test Configuration  --------------------------- */
#define BENCH_EMBEDDED
#define NO_MAIN_DRIVER

#endif /* USER_SETTINGS_STM32SIM_F417_H */
