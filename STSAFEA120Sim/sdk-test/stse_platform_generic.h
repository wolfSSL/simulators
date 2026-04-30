/* stse_platform_generic.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of STSAFEA120Sim.
 *
 * STSAFEA120Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * STSAFEA120Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * STSELib platform-specific type definitions for Linux x86_64/ARM.
 * STSELib's core/stse_platform.h includes this file and expects the
 * PLAT_UI8 / PLAT_UI16 / PLAT_UI32 typedefs plus PLAT_PACKED_STRUCT
 * to be defined here.
 */

#ifndef STSE_PLATFORM_GENERIC_H
#define STSE_PLATFORM_GENERIC_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef __WEAK
#define __WEAK __attribute__((weak))
#endif

typedef uint8_t  PLAT_UI8;
typedef uint16_t PLAT_UI16;
typedef uint32_t PLAT_UI32;
typedef uint64_t PLAT_UI64;
typedef int8_t   PLAT_I8;
typedef int16_t  PLAT_I16;
typedef int32_t  PLAT_I32;
typedef int64_t  PLAT_I64;

#define PLAT_PACKED_STRUCT __attribute__((packed))

#endif /* STSE_PLATFORM_GENERIC_H */
