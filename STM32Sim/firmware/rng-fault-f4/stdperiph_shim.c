/* stdperiph_shim.c
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

#include "stm32f4xx.h"

void RCC_AHB2PeriphClockCmd(uint32_t RCC_AHB2Periph, FunctionalState NewState)
{
    if (NewState != DISABLE) {
        RCC->AHB2ENR |= RCC_AHB2Periph;
    }
    else {
        RCC->AHB2ENR &= ~RCC_AHB2Periph;
    }
}

void RCC_AHB2PeriphResetCmd(uint32_t RCC_AHB2Periph, FunctionalState NewState)
{
    if (NewState != DISABLE) {
        RCC->AHB2RSTR |= RCC_AHB2Periph;
    }
    else {
        RCC->AHB2RSTR &= ~RCC_AHB2Periph;
    }
}

void RNG_DeInit(void)
{
    RCC_AHB2PeriphResetCmd(RCC_AHB2Periph_RNG, ENABLE);
    RCC_AHB2PeriphResetCmd(RCC_AHB2Periph_RNG, DISABLE);
}

void RNG_Cmd(FunctionalState NewState)
{
    if (NewState != DISABLE) {
        RNG->CR |= RNG_CR_RNGEN;
    }
    else {
        RNG->CR &= ~RNG_CR_RNGEN;
    }
}

uint32_t RNG_GetRandomNumber(void)
{
    return RNG->DR;
}

FlagStatus RNG_GetFlagStatus(uint8_t RNG_FLAG)
{
    return ((RNG->SR & RNG_FLAG) != 0U) ? SET : RESET;
}

/* SEIS/CEIS sit four bits above SECS/CECS and are cleared by writing 0;
 * the status bits below them are read-only. */
void RNG_ClearFlag(uint8_t RNG_FLAG)
{
    RNG->SR = ~(uint32_t)(((uint32_t)RNG_FLAG) << 4);
}
