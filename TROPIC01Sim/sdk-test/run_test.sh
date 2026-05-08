#!/bin/bash
# run_test.sh
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of TROPIC01Sim.
#
# TROPIC01Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# bash (not /bin/sh) is required for the /dev/tcp readiness probe.

set -eu

SIM_BIN="${SIM_BIN:-/app/tcp_server}"
TEST_BIN="${TEST_BIN:-/app/libtropic/examples/model/sim_test/build/tropic01_sim_test}"
SIM_PORT="${TROPIC01_SIM_PORT:-28992}"
SIM_HOST="${TROPIC01_SIM_HOST:-127.0.0.1}"

export TROPIC01_SIM_BIND="${TROPIC01_SIM_BIND:-127.0.0.1}"
export TROPIC01_SIM_PORT="${SIM_PORT}"
export TROPIC01_SIM_HOST="${SIM_HOST}"
export TROPIC01_SIM_FRESH=1

cleanup() {
    if [ -n "${SIM_PID:-}" ] && kill -0 "${SIM_PID}" 2>/dev/null; then
        kill "${SIM_PID}" 2>/dev/null || true
        wait "${SIM_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

"${SIM_BIN}" &
SIM_PID=$!

# Wait up to 5s for the listener to come up.
SIM_READY=0
for i in $(seq 1 50); do
    if (echo > /dev/tcp/"${SIM_HOST}"/"${SIM_PORT}") 2>/dev/null; then
        SIM_READY=1
        break
    fi
    sleep 0.1
done
if [ "${SIM_READY}" -ne 1 ]; then
    echo "ERROR: tropic01 simulator did not start listening on ${SIM_HOST}:${SIM_PORT} within 5s" >&2
    exit 1
fi

"${TEST_BIN}"
RC=$?
exit $RC
