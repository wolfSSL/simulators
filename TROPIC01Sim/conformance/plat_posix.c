/* plat_posix.c
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

/*
 * POSIX platform for the conformance probe: libtropic's TCP HAL talking to
 * TROPIC01Sim at TROPIC01_SIM_HOST:TROPIC01_SIM_PORT (default
 * 127.0.0.1:28992).
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libtropic.h"
#include "libtropic_wolfcrypt.h"
#include "libtropic_port_posix_tcp.h"

#include "tr01_conf.h"

static lt_dev_posix_tcp_t dev;
static lt_ctx_wolfcrypt_t cctx;

void plat_setup_handle(lt_handle_t* h)
{
    const char* host = getenv("TROPIC01_SIM_HOST");
    const char* port = getenv("TROPIC01_SIM_PORT");

    memset(&dev, 0, sizeof(dev));
    dev.addr = inet_addr(host ? host : "127.0.0.1");
    dev.port = (in_port_t)(port ? atoi(port) : 28992);
    h->l2.device     = &dev;
    h->l3.crypto_ctx = &cctx;
}

void plat_delay_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

/* Seed for wolfCrypt's DRBG (libtropic's CAL uses it for the handshake) */
int conf_host_seed(unsigned char* out, unsigned int sz)
{
    FILE*  f = fopen("/dev/urandom", "rb");
    size_t n = 0;

    if (f != NULL) {
        n = fread(out, 1, sz, f);
        fclose(f);
    }
    return (n == sz) ? 0 : -1;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("=== TROPIC01 conformance (emulator) ===\n");
    return tr01_conf_run();
}
