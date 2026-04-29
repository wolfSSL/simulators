/* hal_tcp.c
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
 * socket to the Rust ATECC608A simulator. See hal_tcp.h for the public API.
 *
 * Implementation notes
 *  - cryptoauthlib's `atcacustom` union doesn't give us a clean way to stash
 *    per-instance state on the HAL object, and this binary only ever talks
 *    to one device, so we keep the socket in a file-static and protect it
 *    with a mutex against cryptoauthlib's own threading.
 *  - The union inside ATCAIfaceCfg is anonymous (no `.cfg.` prefix) in the
 *    v3.7.x release we're pinning against.
 */
#include "hal_tcp.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8608

static int g_fd = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Tracing is enabled only when HAL_TCP_TRACE is set AND non-empty, so that
 * shell scripts using `export HAL_TCP_TRACE=${HAL_TCP_TRACE:-}` (empty by
 * default) don't accidentally turn it on. */
static int trace_enabled(void) {
    const char *t = getenv("HAL_TCP_TRACE");
    return t && *t;
}

static int parse_port(const char *s) {
    if (!s) return DEFAULT_PORT;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || v <= 0 || v > 65535) return DEFAULT_PORT;
    return (int)v;
}

static int tcp_connect(void) {
    const char *host = getenv("ATECC608_SIM_HOST");
    if (!host || !*host) host = DEFAULT_HOST;
    int port = parse_port(getenv("ATECC608_SIM_PORT"));

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_s[8];
    snprintf(port_s, sizeof port_s, "%d", port);

    int rc = getaddrinfo(host, port_s, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[hal_tcp] getaddrinfo(%s:%d): %s\n", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "[hal_tcp] unable to connect to %s:%d: %s\n",
                host, port, strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int ensure_connected(void) {
    if (g_fd >= 0) return 0;
    g_fd = tcp_connect();
    return g_fd < 0 ? -1 : 0;
}

ATCA_STATUS hal_tcp_init(void *hal, void *cfg) {
    (void)hal;
    (void)cfg;
    pthread_mutex_lock(&g_lock);
    int r = ensure_connected();
    pthread_mutex_unlock(&g_lock);
    return r < 0 ? ATCA_COMM_FAIL : ATCA_SUCCESS;
}

ATCA_STATUS hal_tcp_post_init(void *iface) {
    (void)iface;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_tcp_send(void *iface, uint8_t word_address,
                         uint8_t *txdata, int txlength) {
    (void)iface;
    pthread_mutex_lock(&g_lock);
    if (ensure_connected() < 0) { pthread_mutex_unlock(&g_lock); return ATCA_COMM_FAIL; }
    uint8_t wa = word_address;
    ATCA_STATUS st = ATCA_SUCCESS;
    if (trace_enabled()) {
        fprintf(stderr, "[hal_tcp] SEND word_addr=0x%02X txlen=%d:", word_address, txlength);
        for (int i = 0; i < txlength && i < 32; ++i) fprintf(stderr, " %02X", txdata[i]);
        fprintf(stderr, "\n");
    }
    if (write_all(g_fd, &wa, 1) < 0) st = ATCA_COMM_FAIL;
    else if (txlength > 0 && txdata && write_all(g_fd, txdata, (size_t)txlength) < 0)
        st = ATCA_COMM_FAIL;
    pthread_mutex_unlock(&g_lock);
    return st;
}

ATCA_STATUS hal_tcp_receive(void *iface, uint8_t word_address,
                            uint8_t *rxdata, uint16_t *rxlength) {
    (void)iface;
    (void)word_address;
    if (!rxdata || !rxlength || *rxlength < 1) return ATCA_BAD_PARAM;
    /* cryptoauthlib's calib_execute_receive does its own two-phase read
     * (1-byte count probe followed by count-1 more bytes). We just read
     * exactly `*rxlength` bytes off the socket — the simulator writes the
     * full response in one send, so subsequent reads get the remainder. */
    pthread_mutex_lock(&g_lock);
    ATCA_STATUS st = ATCA_SUCCESS;
    if (g_fd < 0) st = ATCA_COMM_FAIL;
    else if (read_all(g_fd, rxdata, *rxlength) < 0) st = ATCA_COMM_FAIL;
    if (trace_enabled()) {
        if (st == ATCA_SUCCESS) {
            fprintf(stderr, "[hal_tcp] RECV rxlen=%u:", (unsigned)*rxlength);
            for (unsigned i = 0; i < *rxlength && i < 80; ++i) fprintf(stderr, " %02X", rxdata[i]);
            fprintf(stderr, "\n");
        } else {
            fprintf(stderr, "[hal_tcp] RECV FAILED (st=0x%02X, wanted %u bytes)\n",
                    st, (unsigned)*rxlength);
        }
    }
    pthread_mutex_unlock(&g_lock);
    return st;
}

ATCA_STATUS hal_tcp_wake(void *iface) {
    /* Matches the simulator's wire contract: the wake pulse is silent —
     * no 4-byte wake response is emitted. cryptoauthlib v3.7+ doesn't
     * call this path anyway (it drives wake via halsend(0x00) + the next
     * halreceive), but leave the hook correct for any caller that does. */
    (void)iface;
    pthread_mutex_lock(&g_lock);
    ATCA_STATUS st = ATCA_SUCCESS;
    if (ensure_connected() < 0) st = ATCA_COMM_FAIL;
    else {
        uint8_t wake = 0x00;
        if (write_all(g_fd, &wake, 1) < 0) st = ATCA_COMM_FAIL;
    }
    pthread_mutex_unlock(&g_lock);
    return st;
}

static ATCA_STATUS send_control(uint8_t byte) {
    pthread_mutex_lock(&g_lock);
    ATCA_STATUS st = ATCA_SUCCESS;
    if (g_fd < 0) st = ATCA_COMM_FAIL;
    else if (write_all(g_fd, &byte, 1) < 0) st = ATCA_COMM_FAIL;
    pthread_mutex_unlock(&g_lock);
    return st;
}

ATCA_STATUS hal_tcp_idle(void *iface) { (void)iface; return send_control(0x02); }
ATCA_STATUS hal_tcp_sleep(void *iface) { (void)iface; return send_control(0x01); }

ATCA_STATUS hal_tcp_release(void *hal_data) {
    (void)hal_data;
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    pthread_mutex_unlock(&g_lock);
    return ATCA_SUCCESS;
}

void hal_tcp_make_cfg(ATCAIfaceCfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->iface_type = ATCA_CUSTOM_IFACE;
    cfg->devtype = ATECC608A;
    cfg->wake_delay = 1500;
    cfg->rx_retries = 20;
    cfg->atcacustom.halinit      = hal_tcp_init;
    cfg->atcacustom.halpostinit  = hal_tcp_post_init;
    cfg->atcacustom.halsend      = hal_tcp_send;
    cfg->atcacustom.halreceive   = hal_tcp_receive;
    cfg->atcacustom.halwake      = hal_tcp_wake;
    cfg->atcacustom.halidle      = hal_tcp_idle;
    cfg->atcacustom.halsleep     = hal_tcp_sleep;
    cfg->atcacustom.halrelease   = hal_tcp_release;
}
