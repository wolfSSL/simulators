#!/bin/bash
set -e

echo "=== Starting SE050 Simulator ==="
/app/se050-sim-server &
SIM_PID=$!
sleep 1

if ! kill -0 $SIM_PID 2>/dev/null; then
    echo "ERROR: Simulator failed to start"
    exit 1
fi

export SE050_SIM_HOST=127.0.0.1
export SE050_SIM_PORT=8050
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

echo ""
/app/test_se050
TEST_RESULT=$?

kill $SIM_PID 2>/dev/null || true
wait $SIM_PID 2>/dev/null || true

exit $TEST_RESULT
