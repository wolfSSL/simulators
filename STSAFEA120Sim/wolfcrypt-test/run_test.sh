#!/bin/bash
# run_test.sh
#
# bash (not /bin/sh) is required: the readiness probe below uses
# /dev/tcp, which is a bash builtin. Debian/Ubuntu's /bin/sh is dash
# and does not support it.
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of STSAFEA120Sim.
#
# STSAFEA120Sim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

set -eu

SIM_BIN="${SIM_BIN:-/app/tcp_server}"
TEST_BIN="${TEST_BIN:-/app/wolfcrypt_stsafe_test}"
SIM_PORT="${STSAFE_SIM_PORT:-8120}"
SIM_HOST="${STSAFE_SIM_HOST:-127.0.0.1}"

export STSAFE_SIM_BIND="${STSAFE_SIM_BIND:-127.0.0.1}"
export STSAFE_SIM_PORT="${SIM_PORT}"
export STSAFE_SIM_HOST="${SIM_HOST}"
export STSAFE_SIM_FRESH=1

cleanup() {
    if [ -n "${SIM_PID:-}" ] && kill -0 "${SIM_PID}" 2>/dev/null; then
        kill "${SIM_PID}" 2>/dev/null || true
        wait "${SIM_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

"${SIM_BIN}" &
SIM_PID=$!

for i in $(seq 1 50); do
    if (echo > /dev/tcp/"${SIM_HOST}"/"${SIM_PORT}") 2>/dev/null; then
        break
    fi
    sleep 0.1
done

"${TEST_BIN}"
exit $?
