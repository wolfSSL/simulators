/* hal_tcp.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of ATECC608Sim.
 *
 * ATECC608Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * ATECC608Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Custom cryptoauthlib HAL that tunnels ATCA command packets over a TCP
 * socket to the Rust ATECC608A simulator.
 *
 * Register by populating an `ATCAIfaceCfg` with `iface_type = ATCA_CUSTOM_IFACE`
 * and the `atcacustom.hal*` function pointers pointing at the symbols below.
 * The helper `hal_tcp_make_cfg()` builds a default cfg that reads host+port
 * from the `ATECC608_SIM_HOST` and `ATECC608_SIM_PORT` env vars (defaulting
 * to 127.0.0.1:8608).
 */
#ifndef HAL_TCP_H
#define HAL_TCP_H

#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

ATCA_STATUS hal_tcp_init(void *hal, void *cfg);
ATCA_STATUS hal_tcp_post_init(void *iface);
ATCA_STATUS hal_tcp_send(void *iface, uint8_t word_address,
                         uint8_t *txdata, int txlength);
ATCA_STATUS hal_tcp_receive(void *iface, uint8_t word_address,
                            uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_tcp_wake(void *iface);
ATCA_STATUS hal_tcp_idle(void *iface);
ATCA_STATUS hal_tcp_sleep(void *iface);
ATCA_STATUS hal_tcp_release(void *hal_data);

/* Populate `cfg` with the right function pointers + a fresh defaults block.
 * The returned cfg is suitable for passing straight to `atcab_init()`. */
void hal_tcp_make_cfg(ATCAIfaceCfg *cfg);

#ifdef __cplusplus
}
#endif

#endif /* HAL_TCP_H */
