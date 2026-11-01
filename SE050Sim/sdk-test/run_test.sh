#!/bin/bash
set -e

KEYFILE=/app/scp03_keys.txt

export SE050_SIM_HOST=127.0.0.1
export SE050_SIM_PORT=8050
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# The simulator personality must match the applet generation the SDK was
# compiled for, or session open aborts on the version check.
if [ "$SE05X_VER" = "03_XX" ]; then
    export SE050_SIM_APPLET=3
    echo "=== Applet personality: 3.1.1 (SDK built for 03_XX) ==="
fi

# Platform SCP03 variant: provision the simulator and the SDK from the same
# key file so the two sides cannot drift.
case "$SE05X_AUTH" in *PlatfSCP03) PLATFSCP=1 ;; *) PLATFSCP=0 ;; esac
if [ "$PLATFSCP" = 1 ]; then
    echo "=== Platform SCP03 variant: provisioning keys from $KEYFILE ==="
    export SE050_SIM_SCP03_ENC=$(awk '/^ENC /{print $2}' "$KEYFILE")
    export SE050_SIM_SCP03_MAC=$(awk '/^MAC /{print $2}' "$KEYFILE")
    export EX_SSS_BOOT_SCP03_PATH="$KEYFILE"
    echo "  simulator ENC=$SE050_SIM_SCP03_ENC"
    echo "  simulator MAC=$SE050_SIM_SCP03_MAC"
fi

# Applet session variants: the SDK opens a UserID / AESKey / ECKey session with
# its demo Authentication Objects (ex_sss_auth.h); the simulator provisions them.
case "$SE05X_AUTH" in
    UserID*|AESKey*|ECKey*)
        echo "=== Applet session variant ($SE05X_AUTH): demo Authentication Objects ==="
        export SE050_SIM_DEMO_AUTH=1
        ;;
esac

start_sim() {
    /app/se050-sim-server &
    SIM_PID=$!
    sleep 1
    if ! kill -0 "$SIM_PID" 2>/dev/null; then
        echo "ERROR: Simulator failed to start"
        exit 1
    fi
}

stop_sim() {
    kill "$SIM_PID" 2>/dev/null || true
    wait "$SIM_PID" 2>/dev/null || true
}

echo "=== Starting SE050 Simulator ==="
start_sim

echo ""
# Do not let a test failure abort the script before cleanup.
set +e
/app/test_se050
TEST_RESULT=$?
set -e

stop_sim

# SCP03 negative check: with a wrong host ENC key the handshake must fail, so
# the SDK cannot open a session. Proves the SCP03 path is not a no-op.
if [ "$SE05X_AUTH" = "PlatfSCP03" ] && [ "$TEST_RESULT" -eq 0 ]; then
    echo ""
    echo "=== SCP03 negative check: a wrong key must be rejected ==="
    BADFILE=/tmp/scp03_bad_keys.txt
    printf 'ENC FF0102030405060708090A0B0C0D0E0F\nMAC 101112131415161718191A1B1C1D1E1F\n' > "$BADFILE"
    export EX_SSS_BOOT_SCP03_PATH="$BADFILE"
    start_sim
    if /app/test_se050 >/dev/null 2>&1; then
        echo "ERROR: session open with a wrong key unexpectedly succeeded"
        stop_sim
        exit 1
    fi
    echo "OK: wrong key rejected (session could not be opened)"
    stop_sim
    export EX_SSS_BOOT_SCP03_PATH="$KEYFILE"
fi

exit "$TEST_RESULT"
