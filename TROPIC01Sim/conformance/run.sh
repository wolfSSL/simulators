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
# compare its "T" lines with the hardware baseline.
#
#   run.sh [SIM_BIN] [PROBE_BIN] [BASELINE]
#
# Exits 0 when the simulator behaves exactly like the chip the baseline was
# recorded on. The probe's full output is kept in $LOG (default
# conformance.log in the current directory).

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SIM_BIN="${1:-$HERE/../tropic01-sim/target/release/tcp_server}"
PROBE_BIN="${2:-$HERE/build/tr01_conf}"
BASELINE="${3:-$HERE/baseline/hw-es-0.1.2.txt}"
LOG="${LOG:-conformance.log}"
PORT="${TROPIC01_SIM_PORT:-28993}"

WORK="$(mktemp -d)"
cleanup() {
    if [ -n "${SIM_PID:-}" ]; then
        kill "${SIM_PID}" 2>/dev/null || true
        wait "${SIM_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

TROPIC01_SIM_FRESH=1 TROPIC01_SIM_BIND=127.0.0.1 TROPIC01_SIM_PORT="${PORT}" \
    TROPIC01_SIM_STORE="${WORK}/store.json" \
    "${SIM_BIN}" > "${WORK}/sim.log" 2>&1 &
SIM_PID=$!

# Wait for this simulator to report that it is listening, so the probe can
# never talk to another one that already holds the port.
READY=0
for _ in $(seq 1 50); do
    if ! kill -0 "${SIM_PID}" 2>/dev/null; then
        echo "ERROR: simulator exited during start-up:" >&2
        cat "${WORK}/sim.log" >&2
        exit 1
    fi
    if grep -q "listening on 127.0.0.1:${PORT}\$" "${WORK}/sim.log"; then
        READY=1
        break
    fi
    sleep 0.1
done
if [ "${READY}" -ne 1 ]; then
    echo "ERROR: simulator did not start on port ${PORT}" >&2
    cat "${WORK}/sim.log" >&2
    exit 1
fi

TROPIC01_SIM_HOST=127.0.0.1 TROPIC01_SIM_PORT="${PORT}" \
    "${PROBE_BIN}" > "${LOG}" 2>&1
RC=$?
if [ "${RC}" -ne 0 ] || ! grep -q "^CONFORMANCE DONE" "${LOG}"; then
    echo "ERROR: probe failed (rc=${RC}), see ${LOG}" >&2
    tail -5 "${LOG}" >&2
    exit 1
fi

grep '^T ' "${BASELINE}" > "${WORK}/expected"
grep '^T ' "${LOG}" > "${WORK}/actual"
CHECKS=$(wc -l < "${WORK}/expected" | tr -d ' ')
if diff -u "${WORK}/expected" "${WORK}/actual" > "${WORK}/diff"; then
    echo "Conformance: all ${CHECKS} checks match $(basename "${BASELINE}")"
    exit 0
fi
echo "Conformance: simulator differs from $(basename "${BASELINE}"):"
cat "${WORK}/diff"
exit 1
