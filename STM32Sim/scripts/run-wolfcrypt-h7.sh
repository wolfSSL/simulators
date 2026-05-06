#!/bin/bash
# run-wolfcrypt-h7.sh
#
# Copyright (C) 2026 wolfSSL Inc.
#
# Build the wolfCrypt-on-STM32H753 firmware (sources baked into the
# image at /opt/firmware-h7) against the user's mounted wolfSSL tree,
# then run the resulting ELF through stm32-sim.
set -euo pipefail

WOLFSSL_ROOT="${WOLFSSL_ROOT:-/opt/wolfssl}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/opt/firmware-h7}"
TIMEOUT="${TIMEOUT:-300}"

if [[ ! -d "${WOLFSSL_ROOT}" ]]; then
    echo "ERROR: wolfSSL source not mounted at ${WOLFSSL_ROOT}" >&2
    exit 2
fi

# Snapshot the wolfSSL tree into a writable location so we can drop a
# stale autoconf config.h (it would otherwise clash with the
# user_settings cross-build) without mutating the user's mount.
WOLFSSL_BUILD_TREE=/opt/wolfssl-build-tree
rm -rf "${WOLFSSL_BUILD_TREE}"
cp -r "${WOLFSSL_ROOT}" "${WOLFSSL_BUILD_TREE}"
rm -f "${WOLFSSL_BUILD_TREE}/config.h"

# The HAL config header lives in the firmware tree but needs to be
# discoverable when the HAL .c files compile.
HAL_CONFIG_FILE="$(ls "${FIRMWARE_DIR}"/*hal_conf.h 2>/dev/null | head -1)"
if [[ -n "${HAL_CONFIG_FILE}" ]]; then
    cp "${HAL_CONFIG_FILE}" \
        /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Inc/ || true
fi

echo ">> Building wolfCrypt firmware against wolfSSL at ${WOLFSSL_ROOT} ..."
cmake -G Ninja \
    -DWOLFSSL_USER_SETTINGS=ON \
    -DUSER_SETTINGS_FILE="${FIRMWARE_DIR}/user_settings.h" \
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
    find "${FIRMWARE_DIR}/build" -name "*.elf" 2>/dev/null || true
    exit 1
fi

echo ">> Running ${ELF} on stm32-sim --chip stm32h753 (timeout ${TIMEOUT}s) ..."
LOG="$(mktemp)"
set +e
stm32-sim \
    --chip stm32h753 \
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

# Fall back to the simulator's exit code if the pass/fail string never
# appeared. exit==3 is timeout, ==4 is fault, ==2 is internal error.
echo
echo "wolfCrypt tests did not report a result string. Simulator exit=${SIM_EXIT}"
exit "${SIM_EXIT}"
