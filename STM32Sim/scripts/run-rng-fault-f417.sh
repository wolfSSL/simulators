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
# STM32F4 RNG fault regression test for wolfSSL's wc_GenerateSeed().
#
# Builds firmware/rng-fault-f4 for both STM32_RNG arms that drive the F4
# RNG directly (the Standard Peripheral Library arm and
# WOLFSSL_STM32_RNG_NOLIB) and runs each on stm32-sim --chip stm32f417
# with RNG seed / clock errors injected part way through a seed request.
# Every scenario must return the expected code and leave the crypto
# hardware mutex released; a hung wc_GenerateSeed() shows up as a simulator
# timeout and fails the test with the hung PC.

set -euo pipefail

WOLFSSL_ROOT="${WOLFSSL_ROOT:-/opt/wolfssl}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/opt/firmware-rng-fault-f4}"
TIMEOUT="${TIMEOUT:-20}"

if [[ ! -d "${WOLFSSL_ROOT}" ]]; then
    echo "ERROR: wolfSSL source not mounted at ${WOLFSSL_ROOT}" >&2
    exit 2
fi

BUILD_DIR="$(mktemp -d)"
cp -r "${FIRMWARE_DIR}/." "${BUILD_DIR}/"

# The sanity seed reads 64 RNG words, so a fault after 200 reads lands
# inside the second, faulted, seed request. RNG_FAILURE_E is -199.
#
#   arm        fault              expected fault= value(s)
SCENARIOS="
stdperiph  none               0
stdperiph  seed:200           0
stdperiph  seed:200:sticky    -199
stdperiph  clock:200          0
stdperiph  clock:200:sticky   -199
nolib      none               0
nolib      seed:200           0
nolib      seed:200:sticky    -199
nolib      clock:200          0
nolib      clock:200:sticky   -199
"

# Drop any build output copied along with the sources, so every run builds
# against WOLFSSL_ROOT afresh.
make -s -C "${BUILD_DIR}" clean
for arm in stdperiph nolib; do
    echo ">> Building rng-fault firmware (${arm} arm) against ${WOLFSSL_ROOT} ..."
    make -s -C "${BUILD_DIR}" TARGET=sim ARM="${arm}" WOLFSSL_ROOT="${WOLFSSL_ROOT}"
done

FAILED=0
while read -r arm fault expect; do
    [[ -z "${arm}" ]] && continue
    elf="${BUILD_DIR}/rng-fault-${arm}-sim.elf"
    args=(--chip stm32f417 --timeout "${TIMEOUT}")
    [[ "${fault}" != "none" ]] && args+=(--rng-fault "${fault}")

    set +e
    out="$(stm32-sim "${args[@]}" "${elf}" 2>&1)"
    rc=$?
    set -e

    got="$(sed -n 's/.*RNG_FAULT sanity=[-0-9]* fault=\([-0-9]*\).*/\1/p' <<<"${out}")"
    sanity="$(sed -n 's/.*RNG_FAULT sanity=\([-0-9]*\).*/\1/p' <<<"${out}")"
    mutex="$(sed -n 's/.*RNG_FAULT .* mutex=\([a-z]*\).*/\1/p' <<<"${out}")"
    label="$(printf '%-9s %-17s' "${arm}" "${fault}")"
    if [[ ${rc} -eq 3 ]]; then
        pc="$(sed -n 's/.*TIMEOUT.*PC=\(0x[0-9a-f]*\).*/\1/p' <<<"${out}")"
        where="$(arm-none-eabi-addr2line -f -e "${elf}" "${pc}" 2>/dev/null | head -1)"
        echo "FAIL  ${label} hung: no return after ${TIMEOUT}s, PC ${pc} in ${where}"
        FAILED=1
    elif [[ "${mutex}" != "ok" ]]; then
        echo "FAIL  ${label} crypto hardware mutex not released (fault=${got}, mutex='${mutex}')"
        FAILED=1
    elif [[ "${sanity}" != "0" ]]; then
        echo "FAIL  ${label} sanity seed returned '${sanity}' (sim exit ${rc})"
        echo "${out}" | tail -5
        FAILED=1
    elif [[ "|${expect}|" == *"|${got}|"* ]]; then
        echo "ok    ${label} fault=${got} mutex=ok"
    else
        echo "FAIL  ${label} fault=${got}, expected ${expect} (sim exit ${rc})"
        FAILED=1
    fi
done <<<"${SCENARIOS}"

rm -rf "${BUILD_DIR}"
if [[ ${FAILED} -ne 0 ]]; then
    echo
    echo "RNG fault tests FAILED."
    exit 1
fi
echo
echo "RNG fault tests completed successfully."
