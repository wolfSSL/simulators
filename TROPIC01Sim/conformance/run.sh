#!/bin/bash
# run.sh
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of TROPIC01Sim.
#
# TROPIC01Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# Run the conformance probe against a freshly provisioned simulator and
# compare its "T" lines with a hardware baseline.
#
#   run.sh [SIM_BIN] [PROBE_BIN] [BASELINE]
#
# A baseline named hw-<personality>.txt is compared with a simulator
# running that personality (TROPIC01_SIM_PERSONALITY overrides it). Without
# BASELINE every baseline in baseline/ is checked in turn.
#
# Exits 0 when the simulator behaves exactly like the chip each baseline was
# recorded on. The probe's full output is kept in $LOG (default
# conformance.log in the current directory) for a single baseline, and in
# conformance-<personality>.log for each one otherwise.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SIM_BIN="${1:-$HERE/../tropic01-sim/target/release/tcp_server}"
PROBE_BIN="${2:-$HERE/build/tr01_conf}"
PORT="${TROPIC01_SIM_PORT:-28993}"

WORK="$(mktemp -d)"
SIM_PID=""
stop_sim() {
    if [ -n "${SIM_PID}" ]; then
        kill "${SIM_PID}" 2>/dev/null || true
        wait "${SIM_PID}" 2>/dev/null || true
        SIM_PID=""
    fi
}
cleanup() {
    stop_sim
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# check BASELINE LOG: 0 when the simulator matches BASELINE
check() {
    local baseline="$1" log="$2" name personality ready
    name="$(basename "${baseline}" .txt)"
    personality="${TROPIC01_SIM_PERSONALITY:-${name#hw-}}"
    rm -f "${WORK}/store.json"

    TROPIC01_SIM_PERSONALITY="${personality}" TROPIC01_SIM_FRESH=1 \
        TROPIC01_SIM_BIND=127.0.0.1 TROPIC01_SIM_PORT="${PORT}" \
        TROPIC01_SIM_STORE="${WORK}/store.json" \
        "${SIM_BIN}" > "${WORK}/sim.log" 2>&1 &
    SIM_PID=$!

    # Wait for this simulator to report that it is listening, so the probe
    # can never talk to another one that already holds the port.
    ready=0
    for _ in $(seq 1 50); do
        if ! kill -0 "${SIM_PID}" 2>/dev/null; then
            echo "ERROR: simulator exited during start-up:" >&2
            cat "${WORK}/sim.log" >&2
            SIM_PID=""
            return 1
        fi
        if grep -q "listening on 127.0.0.1:${PORT}\$" "${WORK}/sim.log"; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [ "${ready}" -ne 1 ]; then
        echo "ERROR: simulator did not start on port ${PORT}" >&2
        cat "${WORK}/sim.log" >&2
        stop_sim
        return 1
    fi

    TROPIC01_SIM_HOST=127.0.0.1 TROPIC01_SIM_PORT="${PORT}" \
        "${PROBE_BIN}" > "${log}" 2>&1
    local rc=$?
    stop_sim
    if [ "${rc}" -ne 0 ] || ! grep -q "^CONFORMANCE DONE" "${log}"; then
        echo "ERROR: probe failed (rc=${rc}), see ${log}" >&2
        tail -5 "${log}" >&2
        return 1
    fi

    grep '^T ' "${baseline}" > "${WORK}/expected"
    grep '^T ' "${log}" > "${WORK}/actual"
    local checks
    checks=$(wc -l < "${WORK}/expected" | tr -d ' ')
    if diff -u "${WORK}/expected" "${WORK}/actual" > "${WORK}/diff"; then
        echo "Conformance (${personality}): all ${checks} checks match ${name}.txt"
        return 0
    fi
    echo "Conformance (${personality}): simulator differs from ${name}.txt:"
    cat "${WORK}/diff"
    return 1
}

if [ $# -ge 3 ]; then
    check "$3" "${LOG:-conformance.log}"
    exit $?
fi

RC=0
for baseline in "${HERE}"/baseline/hw-*.txt; do
    name="$(basename "${baseline}" .txt)"
    check "${baseline}" "conformance-${name#hw-}.log" || RC=1
done
exit "${RC}"
