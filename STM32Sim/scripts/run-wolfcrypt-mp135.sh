#!/bin/bash
# run-wolfcrypt-mp135.sh
#
# Copyright (C) 2026 wolfSSL Inc.
#
# Build the wolfCrypt-on-STM32MP135 firmware (sources baked into the
# image at /opt/firmware-mp135) against the user's mounted wolfSSL
# tree, then run the resulting ELF through stm32-sim --chip
# stm32mp135.
#
# The MP135 is a Cortex-A7 (ARMv7-A) part. The simulator boots into
# ARM mode and the firmware sets up a flat 1 MiB-section MMU map
# before exercising any peripherals. wolfSSL needs version 5.8.4+ for
# the WOLFSSL_STM32MP13 / CRYP1 alias support.
set -euo pipefail

WOLFSSL_ROOT="${WOLFSSL_ROOT:-/opt/wolfssl}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/opt/firmware-mp135}"
STM32CUBE_MP13_ROOT="${STM32CUBE_MP13_ROOT:-/opt/STM32CubeMP13}"
TIMEOUT="${TIMEOUT:-300}"

if [[ ! -d "${WOLFSSL_ROOT}" ]]; then
    echo "ERROR: wolfSSL source not mounted at ${WOLFSSL_ROOT}" >&2
    exit 2
fi

WOLFSSL_BUILD_TREE=/opt/wolfssl-build-tree
rm -rf "${WOLFSSL_BUILD_TREE}"
cp -r "${WOLFSSL_ROOT}" "${WOLFSSL_BUILD_TREE}"
rm -f "${WOLFSSL_BUILD_TREE}/config.h"

# Drop the firmware's HAL config header next to the HAL sources so
# stm32mp13xx_hal.h finds it on the include path.
HAL_CONFIG_FILE="$(ls "${FIRMWARE_DIR}"/*hal_conf.h 2>/dev/null | head -1)"
if [[ -n "${HAL_CONFIG_FILE}" ]]; then
    cp "${HAL_CONFIG_FILE}" \
        "${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Inc/" || true
fi

echo ">> Building MP135 wolfCrypt firmware against wolfSSL at ${WOLFSSL_ROOT} ..."
# With WOLFSSL_USER_SETTINGS=ON, wolfSSL's CMake throws away all the
# WOLFSSL_DEFINITIONS it would otherwise build up from -DWOLFSSL_SHA3
# etc. (see line 2300-2302 of wolfssl's CMakeLists.txt). Every
# algorithm choice flows through firmware/wolfcrypt-test-mp135/
# user_settings.h instead - that is where WOLFSSL_SHA3 / SHAKE128 /
# SHAKE256 / SHA384 / SHA512 are turned on so the MP13 HASH IP's
# wider digest set is exercised end-to-end.
cmake -G Ninja \
    -DWOLFSSL_USER_SETTINGS=ON \
    -DUSER_SETTINGS_FILE="${FIRMWARE_DIR}/user_settings.h" \
    -DCMAKE_TOOLCHAIN_FILE="${FIRMWARE_DIR}/toolchain-arm-none-eabi.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    -DWOLFSSL_CRYPT_TESTS=OFF \
    -DWOLFSSL_EXAMPLES=OFF \
    -DWOLFSSL_ROOT="${WOLFSSL_BUILD_TREE}" \
    -DSTM32CUBE_MP13_ROOT="${STM32CUBE_MP13_ROOT}" \
    -B "${FIRMWARE_DIR}/build" \
    -S "${FIRMWARE_DIR}"
cmake --build "${FIRMWARE_DIR}/build"

ELF="${FIRMWARE_DIR}/build/wolfcrypt_test.elf"
if [[ ! -f "${ELF}" ]]; then
    echo "ERROR: firmware build produced no ELF at ${ELF}" >&2
    find "${FIRMWARE_DIR}/build" -name "*.elf" 2>/dev/null || true
    exit 1
fi

echo ">> Running ${ELF} on stm32-sim --chip stm32mp135 (timeout ${TIMEOUT}s) ..."
LOG="$(mktemp)"
set +e
stm32-sim \
    --chip stm32mp135 \
    --timeout "${TIMEOUT}" \
    --exit-on test_complete \
    --result-symbol test_result \
    "${ELF}" 2>&1 | tee "${LOG}"
SIM_EXIT=$?
set -e

if grep -q "=== wolfCrypt test passed! ===" "${LOG}"; then
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
echo "wolfCrypt tests did not report a result string. Simulator exit=${SIM_EXIT}"
exit "${SIM_EXIT}"
