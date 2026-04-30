/* pal_tcp.h
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
 * Minimal Linux PAL for STSELib that pipes the I2C surface over a TCP
 * socket to the STSAFE-A120 simulator. STSELib calls the
 * `stse_platform_*` family declared in core/stse_platform.h; this file
 * provides Linux implementations.
 *
 * Connection target is configured via env vars:
 *   STSAFE_SIM_HOST (default "127.0.0.1")
 *   STSAFE_SIM_PORT (default 8120)
 *
 * The TCP framing prepends a 2-byte big-endian length to each frame in
 * each direction, so the simulator and the host can size their reads
 * without per-call boundary tracking. This is purely a transport
 * convenience and does not exist on real I2C silicon.
 */

#ifndef PAL_TCP_H
#define PAL_TCP_H

#include "stse_platform_generic.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Force a reconnect on the next send. Useful in tests that want to start
 * each scenario from a clean transport state. */
void pal_tcp_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* PAL_TCP_H */
