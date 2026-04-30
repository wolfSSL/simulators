/* test_helpers.h
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

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>

extern int g_failures;
extern int g_run;

#define ASSERT_OK(label, ret)                                                                                                                  \
    do {                                                                                                                                       \
        g_run++;                                                                                                                               \
        if ((ret) != STSE_OK) {                                                                                                                \
            fprintf(stderr, "[FAIL] %s: STSELib returned 0x%02X (expected STSE_OK)\n", (label), (unsigned)(ret));                              \
            g_failures++;                                                                                                                      \
        } else {                                                                                                                               \
            fprintf(stdout, "[ OK ] %s\n", (label));                                                                                           \
        }                                                                                                                                      \
    } while (0)

#define ASSERT_TRUE(label, cond)                                                                                                               \
    do {                                                                                                                                       \
        g_run++;                                                                                                                               \
        if (!(cond)) {                                                                                                                         \
            fprintf(stderr, "[FAIL] %s: expression false\n", (label));                                                                         \
            g_failures++;                                                                                                                      \
        } else {                                                                                                                               \
            fprintf(stdout, "[ OK ] %s\n", (label));                                                                                           \
        }                                                                                                                                      \
    } while (0)

#define ASSERT_EQ_BYTES(label, a, b, n)                                                                                                        \
    do {                                                                                                                                       \
        g_run++;                                                                                                                               \
        if (memcmp((a), (b), (n)) != 0) {                                                                                                      \
            fprintf(stderr, "[FAIL] %s: byte arrays differ\n", (label));                                                                       \
            g_failures++;                                                                                                                      \
        } else {                                                                                                                               \
            fprintf(stdout, "[ OK ] %s\n", (label));                                                                                           \
        }                                                                                                                                      \
    } while (0)

#endif /* TEST_HELPERS_H */
