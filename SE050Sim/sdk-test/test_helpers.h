/* test_helpers.h
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
 * SE050 Simulator SDK Test Helpers
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;
static const char *g_current_test = NULL;

#define TEST_BEGIN(name) \
    do { \
        g_current_test = name; \
        g_tests_run++; \
        printf("%-40s ", name); \
        fflush(stdout); \
    } while (0)

#define TEST_PASS() \
    do { \
        g_tests_passed++; \
        printf("PASS\n"); \
        fflush(stdout); \
        return; \
    } while (0)

#define TEST_FAIL(msg) \
    do { \
        g_tests_failed++; \
        printf("FAIL (%s)\n", msg); \
        fflush(stdout); \
        return; \
    } while (0)

#define TEST_FAILF(fmt, ...) \
    do { \
        g_tests_failed++; \
        printf("FAIL ("); \
        printf(fmt, __VA_ARGS__); \
        printf(")\n"); \
        fflush(stdout); \
        return; \
    } while (0)

#define ASSERT_OK(status, msg) \
    do { \
        if ((status) != kStatus_SSS_Success) { \
            TEST_FAILF("%s: status=%d", msg, (int)(status)); \
        } \
    } while (0)

#define ASSERT_EQ(a, b, msg) \
    do { \
        if ((a) != (b)) { \
            TEST_FAILF("%s: %d != %d", msg, (int)(a), (int)(b)); \
        } \
    } while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) \
    do { \
        if (memcmp((a), (b), (len)) != 0) { \
            TEST_FAIL(msg); \
        } \
    } while (0)

#define ASSERT_MEM_NEQ(a, b, len, msg) \
    do { \
        if (memcmp((a), (b), (len)) == 0) { \
            TEST_FAIL(msg); \
        } \
    } while (0)

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("  %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; i++)
        printf("%02x", data[i]);
    if (len > 32) printf("...");
    printf("\n");
}

static void test_summary(void)
{
    printf("\n=== %d/%d tests passed ===\n", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf("=== %d FAILED ===\n", g_tests_failed);
}

#endif /* TEST_HELPERS_H */
