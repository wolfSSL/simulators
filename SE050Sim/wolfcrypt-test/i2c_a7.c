/* i2c_a7.c
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

/**
 * Custom PAL I2C layer for SE050 Simulator.
 *
 * Replaces the NXP Plug&Trust SDK's platform/linux/i2c_a7.c
 * with a TCP socket transport that connects to the se050-sim-server.
 *
 * Environment variables:
 *   SE050_SIM_HOST - TCP host (default: 127.0.0.1)
 *   SE050_SIM_PORT - TCP port (default: 8050)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

#include "i2c_a7.h"

#define DEFAULT_SIM_HOST "127.0.0.1"
#define DEFAULT_SIM_PORT 8050

/* Connection context holding the socket fd */
typedef struct {
    int sockfd;
} sim_conn_t;

static int read_exact(int fd, unsigned char *buf, int len)
{
    int total = 0;
    while (total < len) {
        int n = read(fd, buf + total, len - total);
        if (n <= 0) {
            fprintf(stderr, "[i2c_sim] read error: %s\n", strerror(errno));
            return -1;
        }
        total += n;
    }
    return 0;
}

static int write_all(int fd, const unsigned char *buf, int len)
{
    int total = 0;
    while (total < len) {
        int n = write(fd, buf + total, len - total);
        if (n <= 0) {
            fprintf(stderr, "[i2c_sim] write error: %s\n", strerror(errno));
            return -1;
        }
        total += n;
    }
    return 0;
}

i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    const char *host;
    int port;
    struct sockaddr_in addr;
    sim_conn_t *ctx;
    int flag = 1;

    (void)pDevName;

    host = getenv("SE050_SIM_HOST");
    if (!host) host = DEFAULT_SIM_HOST;

    {
        const char *port_str = getenv("SE050_SIM_PORT");
        port = port_str ? atoi(port_str) : DEFAULT_SIM_PORT;
    }

    ctx = (sim_conn_t *)calloc(1, sizeof(sim_conn_t));
    if (!ctx) return I2C_FAILED;

    ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->sockfd < 0) {
        fprintf(stderr, "[i2c_sim] socket() failed: %s\n", strerror(errno));
        free(ctx);
        return I2C_FAILED;
    }

    /* Disable Nagle's algorithm for low latency */
    setsockopt(ctx->sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        fprintf(stderr, "[i2c_sim] invalid host: %s\n", host);
        close(ctx->sockfd);
        free(ctx);
        return I2C_FAILED;
    }

    if (connect(ctx->sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[i2c_sim] connect(%s:%d) failed: %s\n",
                host, port, strerror(errno));
        close(ctx->sockfd);
        free(ctx);
        return I2C_FAILED;
    }

    fprintf(stderr, "[i2c_sim] Connected to SE050 simulator at %s:%d\n", host, port);
    fflush(stderr);
    *conn_ctx = ctx;
    return I2C_OK;
}

/* Debug: trace I2C operations */
static void trace_hex(const char *label, const unsigned char *data, int len) {
    fprintf(stderr, "[i2c_sim] %s (%d bytes): ", label, len);
    for (int i = 0; i < len && i < 32; i++)
        fprintf(stderr, "%02x ", data[i]);
    if (len > 32) fprintf(stderr, "...");
    fprintf(stderr, "\n");
    fflush(stderr);
}

void axI2CTerm(void *conn_ctx, int mode)
{
    sim_conn_t *ctx = (sim_conn_t *)conn_ctx;
    (void)mode;
    if (ctx) {
        close(ctx->sockfd);
        free(ctx);
    }
}

i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus,
                       unsigned char addr, unsigned char *pTx,
                       unsigned short txLen)
{
    sim_conn_t *ctx = (sim_conn_t *)conn_ctx;
    (void)bus;
    (void)addr;

    if (!ctx || ctx->sockfd < 0) return I2C_FAILED;

    if (write_all(ctx->sockfd, pTx, txLen) < 0)
        return I2C_FAILED;

    trace_hex("WRITE", pTx, txLen);
    return I2C_OK;
}

i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus,
                      unsigned char addr, unsigned char *pRx,
                      unsigned short rxLen)
{
    sim_conn_t *ctx = (sim_conn_t *)conn_ctx;
    ssize_t n;
    (void)bus;
    (void)addr;

    if (!ctx || ctx->sockfd < 0) return I2C_FAILED;

    /*
     * Emulate I2C read behavior over TCP:
     *
     * On real I2C, if the SE050 has no data ready, the read gets a NACK
     * (I2C_FAILED). The SDK retries with a polling delay.
     *
     * We use poll() to check if data is available. If the socket has data,
     * we read it. If not, we return I2C_FAILED to trigger the SDK's retry
     * logic with its polling delay (ESE_POLL_DELAY_MS).
     *
     * When data IS available, we read what's there and zero-fill the rest
     * (simulating I2C clock-stretching where the device sends 0x00 after
     * the actual frame data).
     */
    {
        struct pollfd pfd;
        pfd.fd = ctx->sockfd;
        pfd.events = POLLIN;
        /* Wait up to 100ms for data - similar to I2C timeout */
        int ready = poll(&pfd, 1, 100);
        if (ready <= 0 || !(pfd.revents & POLLIN)) {
            return I2C_FAILED;  /* No data available - like I2C NACK */
        }
    }

    if (rxLen >= 260) {
        /* Initial buffer flush (MAX_DATA_LEN=260):
         * read available data, zero-fill rest. Only used during init. */
        memset(pRx, 0, rxLen);
        n = read(ctx->sockfd, pRx, rxLen);
        if (n <= 0) return I2C_FAILED;
        trace_hex("READ-scan", pRx, (int)(n > 16 ? 16 : n));
    } else {
        /* All frame reads: use read_exact to guarantee all bytes arrive.
         * Handles header reads (2-3 bytes), medium payloads (70 bytes),
         * and large payloads (256+ bytes for multi-frame RSA responses). */
        if (read_exact(ctx->sockfd, pRx, rxLen) < 0)
            return I2C_FAILED;
        trace_hex("READ", pRx, (int)(rxLen > 16 ? 16 : rxLen));
    }
    return I2C_OK;
}

i2c_error_t axI2CWriteByte(void *conn_ctx, unsigned char bus,
                           unsigned char addr, unsigned char *pTx)
{
    return axI2CWrite(conn_ctx, bus, addr, pTx, 1);
}

i2c_error_t axI2CWriteRead(void *conn_ctx, unsigned char bus,
                           unsigned char addr, unsigned char *pTx,
                           unsigned short txLen, unsigned char *pRx,
                           unsigned short *pRxLen)
{
    i2c_error_t rc;
    (void)bus;
    (void)addr;

    rc = axI2CWrite(conn_ctx, bus, addr, pTx, txLen);
    if (rc != I2C_OK) return rc;

    /* Read response - caller provides max length, we read exactly that */
    rc = axI2CRead(conn_ctx, bus, addr, pRx, *pRxLen);
    return rc;
}

void axI2CResetBackoffDelay(void)
{
    /* No-op for simulator */
}
