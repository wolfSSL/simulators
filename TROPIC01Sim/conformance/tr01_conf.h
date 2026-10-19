/* tr01_conf.h
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

/* Platform hooks of the conformance probe: plat_posix.c for TROPIC01Sim
 * over TCP; an MCU build provides the same two functions for its SPI HAL. */
#ifndef TR01_CONF_H
#define TR01_CONF_H
#include "libtropic_common.h"
void plat_setup_handle(lt_handle_t* h);
void plat_delay_ms(uint32_t ms);
int  tr01_conf_run(void);
#endif
