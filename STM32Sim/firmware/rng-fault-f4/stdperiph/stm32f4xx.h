/* stm32f4xx.h
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

/* StdPeriph-style umbrella header. wolfSSL's settings.h includes
 * "stm32f4xx.h" for a WOLFSSL_STM32F4 build with neither
 * WOLFSSL_STM32_CUBEMX nor WOLFSSL_STM32_BARE, expecting the StdPeriph
 * library's device header (which pulls in the peripheral driver headers).
 * This wrapper sits ahead of ST's CMSIS device include directory, pulls in
 * the real CMSIS header and then the StdPeriph shim prototypes. */

#ifndef RNG_FAULT_STM32F4XX_H
#define RNG_FAULT_STM32F4XX_H

#include_next <stm32f4xx.h>
#include "stdperiph_shim.h"

#endif /* RNG_FAULT_STM32F4XX_H */
