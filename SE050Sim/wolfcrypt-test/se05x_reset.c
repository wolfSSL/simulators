/* se05x_reset.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * No-op SE050 reset stub for simulator testing.
 * Replaces platform/rsp/se05x_reset.c which uses GPIO (not available in Docker).
 */

#include <stdint.h>
#include "sm_timer.h"

void axReset_HostConfigure(void) {}
void axReset_HostUnconfigure(void) {}
void axReset_ResetPulseDUT(int reset_logic) { (void)reset_logic; }
void axReset_PowerDown(int reset_logic) { (void)reset_logic; }
void axReset_PowerUp(int reset_logic) { (void)reset_logic; }
void se05x_ic_reset(uint32_t applet_version) { (void)applet_version; }
