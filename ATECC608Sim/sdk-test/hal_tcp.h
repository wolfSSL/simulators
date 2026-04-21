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
