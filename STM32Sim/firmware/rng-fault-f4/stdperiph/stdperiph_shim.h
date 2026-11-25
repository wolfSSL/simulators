/* stdperiph_shim.h
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

/* Minimal stand-in for the STM32F4xx Standard Peripheral Library RNG and
 * RCC calls that wolfSSL's STM32_RNG StdPeriph wc_GenerateSeed() arm uses.
 * ST's StdPeriph library is not vendored here, so these mirror the
 * register-level behaviour of its stm32f4xx_rng.c / stm32f4xx_rcc.c
 * functions of the same names. */

#ifndef STDPERIPH_SHIM_H
#define STDPERIPH_SHIM_H

#include <stdint.h>

#define RCC_AHB2Periph_RNG  ((uint32_t)0x00000040)

#define RNG_FLAG_DRDY       ((uint8_t)0x0001)
#define RNG_FLAG_CECS       ((uint8_t)0x0002)
#define RNG_FLAG_SECS       ((uint8_t)0x0004)

void       RCC_AHB2PeriphClockCmd(uint32_t RCC_AHB2Periph,
                                  FunctionalState NewState);
void       RCC_AHB2PeriphResetCmd(uint32_t RCC_AHB2Periph,
                                  FunctionalState NewState);
void       RNG_DeInit(void);
void       RNG_Cmd(FunctionalState NewState);
uint32_t   RNG_GetRandomNumber(void);
FlagStatus RNG_GetFlagStatus(uint8_t RNG_FLAG);
void       RNG_ClearFlag(uint8_t RNG_FLAG);

#endif /* STDPERIPH_SHIM_H */
