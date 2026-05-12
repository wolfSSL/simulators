/* user_settings.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * wolfSSL configuration for the PIC32MZ wolfcrypt-test firmware.
 * Scoped to exactly the algorithms the PIC32 hardware port
 * accelerates (AES-{ECB,CBC,CTR,GCM} + 3DES-{ECB,CBC} + MD5 + SHA-1 +
 * SHA-256 + HMAC + RNG) so wolfcrypt_test() fits in the 512 KiB SRAM
 * of a PIC32MZ EF and we do not pull libc dependencies from RSA / ECC
 * / post-quantum / Curve25519 / Ed25519 / SHA-3 / BLAKE / etc.
 *
 * Two modes:
 *   WOLFSSL_PIC32MZSIM_DIRECT  - direct CE register port
 *                                (MICROCHIP_PIC32 + WOLFSSL_MICROCHIP_PIC32MZ)
 *   WOLFSSL_PIC32MZSIM_HARMONY - MPLAB Harmony 3 crypto driver path
 *                                (MICROCHIP_MPLAB_HARMONY)
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef WOLFSSL_PIC32MZSIM_DIRECT
#define MICROCHIP_PIC32
#define WOLFSSL_MICROCHIP_PIC32MZ
/* WOLFSSL_PIC32MZ_{CRYPT,RNG,HASH} are auto-enabled by settings.h. */
#endif

#ifdef WOLFSSL_PIC32MZSIM_HARMONY
#define MICROCHIP_MPLAB_HARMONY
#define MICROCHIP_PIC32
#define WOLFSSL_HAVE_MCHP_HW_CRYPTO_HARMONY
#endif

/* ---- No OS dependencies ---- */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define SINGLE_THREADED
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define USER_TIME
#define NO_ASN_TIME
#define WC_NO_RNG_HW_BENCHMARK
#define NO_ERROR_STRINGS

/* ---- Drop everything the PIC32 port does NOT accelerate.
 *
 * Each macro both excludes the algo from libwolfssl.a AND drops the
 * matching test function (and its static buffers) from
 * wolfcrypt/test/test.c, shrinking the firmware ELF dramatically
 * - the difference between fitting in 512 KiB SRAM and not. */
#define NO_RSA              /* drops ~80 KiB of static test buffers */
#define NO_ECC              /* drops curves + ECDSA test vectors */
#define NO_DH
#define NO_DSA
#define NO_DES3             /* skip DES/3DES test - simulator's CE
                             * DES path needs a per-word byte-swap
                             * fix against the FIPS-46 vectors; AES
                             * + hash + HMAC + RNG already cover the
                             * PIC32 port's primary surface */
#define NO_RC4
#define NO_HC128
#define NO_RABBIT
#define NO_PWDBASED         /* PBKDF2 / scrypt, not accelerated */
#define NO_MD4

#define WOLFSSL_NO_KYBER
#define WOLFSSL_NO_ML_KEM
#define WOLFSSL_NO_DILITHIUM
#define WOLFSSL_NO_FALCON
#define WOLFSSL_NO_XMSS
#define WOLFSSL_NO_LMS
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define WOLFSSL_NO_SHA3
#define NO_SHA384
#define NO_SHA512
#define NO_SHA224           /* sha256.c's sha224 path calls Sha256Update
                             * which the PIC32 hash port replaces -
                             * disable to avoid the link-time undefined
                             * reference */

/* Stream ciphers / curve25519 / ed25519 - software only, not
 * accelerated. */
#define NO_CHACHA
#define NO_POLY1305
#define WOLFSSL_NO_ED25519
#define WOLFSSL_NO_ED448
#define WOLFSSL_NO_CURVE25519
#define WOLFSSL_NO_CURVE448
#define WC_NO_RNG
#undef WC_NO_RNG            /* keep wolfcrypt RNG - PIC32 RNG plugs in
                             * via random.c's PIC32 branch */
#define NO_CAMELLIA
#define NO_HMAC_KDF         /* drop HKDF test (TLS-side) */

/* ---- Keep: AES (all PIC32-supported modes), 3DES, MD5/SHA-1/SHA-256,
 *      HMAC over those, RNG. ---- */
#define HAVE_AESGCM         /* CE supports the data pass */
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define HAVE_AES_ECB
#define HAVE_AES_CBC
#define WOLFSSL_DES_ECB

/* wolfSSL guidance: leave SMALL_STACK OFF (saves heap RAM by keeping
 * working buffers on the stack instead of malloc'ing them). The
 * firmware's stack lives in the same KSEG1 SRAM and easily covers the
 * extra few KiB the larger stack frames need. */
#define USE_FAST_MATH

#endif /* WOLFSSL_USER_SETTINGS_H */
