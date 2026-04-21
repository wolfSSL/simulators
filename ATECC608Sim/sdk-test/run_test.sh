#!/bin/bash
set -e

cleanup() {
    if [ -n "${SIM_PID:-}" ]; then
        kill "$SIM_PID" 2>/dev/null || true
        wait "$SIM_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== Starting ATECC608A simulator ==="
/app/atecc608-sim-server &
SIM_PID=$!
sleep 1

if ! kill -0 $SIM_PID 2>/dev/null; then
    echo "ERROR: simulator failed to start"
    exit 1
fi

export ATECC608_SIM_HOST=127.0.0.1
export ATECC608_SIM_PORT=8608
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH

echo ""
# Capture the test's exit code without letting `set -e` tear us down before
# the trap-based cleanup runs.
set +e
/app/test_atecc608
TEST_RESULT=$?
set -e

exit $TEST_RESULT
