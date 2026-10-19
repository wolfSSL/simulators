/* user_settings.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of TROPIC01Sim.
 *
 * TROPIC01Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * TROPIC01Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* wolfCrypt settings for the conformance probe: libtropic's wolfCrypt CAL
 * (X25519, AES-GCM, SHA-256, HMAC) plus P-256 and Ed25519 to check the
 * chip's signatures. */

#ifndef WOLF_USER_SETTINGS_H
#define WOLF_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define NO_FILESYSTEM
#define HAVE_HASHDRBG
int conf_host_seed(unsigned char* out, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED conf_host_seed
#define WOLFSSL_SP_MATH_ALL
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_SHA512
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define NO_RSA
#define NO_DH
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_DSA
#define NO_RC4
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define NO_OLD_TLS

#endif /* WOLF_USER_SETTINGS_H */
