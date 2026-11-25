/* user_settings.h
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

/* Minimal wolfCrypt configuration for the STM32F4 RNG fault test.
 *
 * Default: WOLFSSL_STM32F4 with neither WOLFSSL_STM32_CUBEMX nor
 * WOLFSSL_STM32_BARE, which selects the Standard Peripheral Library arm of
 * wc_GenerateSeed() in wolfcrypt/src/random.c.
 *
 * Build with -DRNG_ARM_NOLIB to select the direct-register
 * WOLFSSL_STM32_RNG_NOLIB arm instead (the comparison case). */

#ifndef USER_SETTINGS_RNG_FAULT_F4_H
#define USER_SETTINGS_RNG_FAULT_F4_H

#define WOLFSSL_STM32F4
#define WOLFSSL_ARM_CORTEX_M

#ifdef RNG_ARM_NOLIB
    #define WOLFSSL_STM32_RNG_NOLIB
#endif

/* This firmware only exercises the RNG. */
#define NO_STM32_HASH
#define NO_STM32_CRYPTO

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define NO_MAIN_DRIVER

#define HAVE_HASHDRBG
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD5
#define NO_SHA
#define NO_AES
#define NO_HMAC
#define NO_PWDBASED
#define NO_ASN
#define NO_CERTS
#define NO_CODING
#define NO_SIG_WRAPPER
#define NO_OLD_TLS
#define NO_PSK
#define NO_BIG_INT
#define WOLFSSL_NO_ASM

#endif /* USER_SETTINGS_RNG_FAULT_F4_H */
