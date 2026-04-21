/* test_helpers.h
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
 * Minimal test scaffolding for the sdk-test suite. No dependencies beyond
 * libc and OpenSSL (brought in by the individual test cases that need it).
 */
#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_OK(call)                                                          \
    do {                                                                         \
        ATCA_STATUS _st = (call);                                                \
        if (_st != ATCA_SUCCESS) {                                               \
            fprintf(stderr, "[FAIL] %s:%d: %s returned 0x%02X\n",               \
                    __FILE__, __LINE__, #call, _st);                             \
            return 1;                                                            \
        }                                                                        \
    } while (0)

#define ASSERT_EQ_INT(a, b)                                                      \
    do {                                                                         \
        long _a = (long)(a), _b = (long)(b);                                     \
        if (_a != _b) {                                                          \
            fprintf(stderr, "[FAIL] %s:%d: expected %ld got %ld\n",             \
                    __FILE__, __LINE__, _b, _a);                                 \
            return 1;                                                            \
        }                                                                        \
    } while (0)

#define ASSERT_EQ_MEM(a, b, n)                                                   \
    do {                                                                         \
        if (memcmp((a), (b), (n)) != 0) {                                        \
            fprintf(stderr, "[FAIL] %s:%d: %zu-byte buffers differ\n",          \
                    __FILE__, __LINE__, (size_t)(n));                            \
            return 1;                                                            \
        }                                                                        \
    } while (0)

#define RUN_TEST(name, fn)                                                       \
    do {                                                                         \
        printf("=== %-32s ", (name));                                            \
        fflush(stdout);                                                          \
        int _r = (fn)();                                                         \
        if (_r == 0) { printf("OK\n"); passed++; }                               \
        else         { printf("FAIL\n"); failed++; }                             \
    } while (0)

#endif /* TEST_HELPERS_H */
