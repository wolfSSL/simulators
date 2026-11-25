#!/usr/bin/env bash
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of STM32Sim.
#
# STM32Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# STM32Sim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# Build the wolfCrypt test for STM32F417 (CubeMX HAL: CRYP for DES/TDES and
# AES ECB/CBC/CTR, HASH for SHA-1/MD5, RNG) and run it on stm32-sim.

set -euo pipefail

WOLFSSL_ROOT="${WOLFSSL_ROOT:-/opt/wolfssl}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/opt/firmware-f417}"
TIMEOUT="${TIMEOUT:-300}"

if [[ ! -d "${WOLFSSL_ROOT}" ]]; then
    echo "ERROR: wolfSSL source not mounted at ${WOLFSSL_ROOT}" >&2
    exit 2
fi

WOLFSSL_BUILD_TREE=/opt/wolfssl-build-tree-f417
rm -rf "${WOLFSSL_BUILD_TREE}"
cp -r "${WOLFSSL_ROOT}" "${WOLFSSL_BUILD_TREE}"
rm -f "${WOLFSSL_BUILD_TREE}/config.h"

echo ">> Building wolfCrypt firmware against wolfSSL at ${WOLFSSL_ROOT} ..."
# WOLFSSL_SINGLE_THREADED keeps wolfSSL's CMake from linking a host
# threads library into the bare-metal image.
cmake -G Ninja \
    -DWOLFSSL_USER_SETTINGS=ON \
    -DWOLFSSL_SINGLE_THREADED=yes \
    -DCMAKE_TOOLCHAIN_FILE="${FIRMWARE_DIR}/toolchain-arm-none-eabi.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DWOLFSSL_CRYPT_TESTS=OFF \
    -DWOLFSSL_EXAMPLES=OFF \
    -DWOLFSSL_ROOT="${WOLFSSL_BUILD_TREE}" \
    -B "${FIRMWARE_DIR}/build" \
    -S "${FIRMWARE_DIR}"
cmake --build "${FIRMWARE_DIR}/build"

ELF="${FIRMWARE_DIR}/build/wolfcrypt_test.elf"
if [[ ! -f "${ELF}" ]]; then
    echo "ERROR: firmware build produced no ELF at ${ELF}" >&2
    exit 1
fi

echo ">> Running ${ELF} on stm32-sim --chip stm32f417 (timeout ${TIMEOUT}s) ..."
LOG="$(mktemp)"
set +e
stm32-sim \
    --chip stm32f417 \
    --timeout "${TIMEOUT}" \
    --exit-on test_complete \
    --result-symbol test_result \
    "${ELF}" 2>&1 | tee "${LOG}"
SIM_EXIT=${PIPESTATUS[0]}
set -e

# The firmware prints its result line before it sets test_complete, so
# the pass marker only counts if the simulator also exited cleanly.
if [[ ${SIM_EXIT} -eq 0 ]] && grep -q "=== wolfCrypt test passed! ===" "${LOG}"; then
    echo
    echo "wolfCrypt tests completed successfully."
    exit 0
fi
if grep -q "=== wolfCrypt test FAILED ===" "${LOG}"; then
    echo
    echo "wolfCrypt tests FAILED."
    exit 1
fi

echo
echo "wolfCrypt tests did not finish cleanly. Simulator exit=${SIM_EXIT}"
if [[ ${SIM_EXIT} -eq 0 ]]; then
    exit 1
fi
exit "${SIM_EXIT}"
