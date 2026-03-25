#!/bin/bash
#
# fwtpm_examples.sh - fwTPM integration test wrapper for make check
#
# Starts the fwTPM server, runs run_examples.sh against it, optionally
# runs tpm2_tools_test.sh, then stops the server.
# Exit: 0 = pass, 77 = skip, non-zero = fail
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

FWTPM_SERVER="$TOP_DIR/src/fwtpm/fwtpm_server"
RUN_EXAMPLES="$TOP_DIR/examples/run_examples.sh"
TPM2_TOOLS_TEST="$TOP_DIR/scripts/tpm2_tools_test.sh"
PID_FILE="/tmp/fwtpm_examples_$$.pid"

PASS=0
FAIL=0
SKIP=0

cleanup() {
    if [ "$STARTED_SERVER" = "1" ] && [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null
        wait "$(cat "$PID_FILE")" 2>/dev/null
        rm -f "$PID_FILE"
        rm -f /tmp/fwtpm.shm
    fi
}
trap cleanup EXIT

# Skip if fwtpm_server not built
if [ ! -x "$FWTPM_SERVER" ]; then
    echo "fwtpm_server not found, skipping fwTPM integration tests"
    exit 77
fi

# Check if a fwtpm_server is already running (e.g. started by CI)
STARTED_SERVER=0
if nc -z localhost 2321 2>/dev/null; then
    echo "fwTPM server already running on port 2321"
else
    # Clean state and start our own server
    killall fwtpm_server 2>/dev/null || true
    sleep 0.3
    rm -f "$TOP_DIR/fwtpm_nv.bin" /tmp/fwtpm.shm
    STARTED_SERVER=1
fi

# Clean stale artifacts
rm -f "$TOP_DIR/fwtpm_nv.bin"
rm -f "$TOP_DIR/rsa_test_blob.raw" "$TOP_DIR/ecc_test_blob.raw" \
      "$TOP_DIR/keyblob.bin"
rm -f "$TOP_DIR"/certs/tpm-*-cert.pem "$TOP_DIR"/certs/tpm-*-cert.csr
rm -f "$TOP_DIR"/certs/server-*-cert.pem "$TOP_DIR"/certs/client-*-cert.pem

# Start fwTPM server if we need to
if [ $STARTED_SERVER -eq 1 ]; then
    "$FWTPM_SERVER" > /tmp/fwtpm_examples_$$.log 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1

    if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "FAIL: fwtpm_server failed to start"
        cat /tmp/fwtpm_examples_$$.log
        exit 1
    fi
    echo "fwTPM server started (pid=$(cat "$PID_FILE"))"
fi

# Run examples
if [ -x "$RUN_EXAMPLES" ]; then
    echo "=== Running run_examples.sh ==="
    cd "$TOP_DIR"
    if "$RUN_EXAMPLES"; then
        PASS=$((PASS + 1))
        echo "PASS: run_examples.sh"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: run_examples.sh"
    fi
else
    echo "SKIP: run_examples.sh not found"
    SKIP=$((SKIP + 1))
fi

# Run tpm2-tools tests if tpm2_tools available
if command -v tpm2_startup > /dev/null 2>&1; then
    if [ -x "$TPM2_TOOLS_TEST" ]; then
        echo ""
        echo "=== Running tpm2_tools_test.sh ==="
        cd "$TOP_DIR"
        if "$TPM2_TOOLS_TEST" --no-start; then
            PASS=$((PASS + 1))
            echo "PASS: tpm2_tools_test.sh"
        else
            FAIL=$((FAIL + 1))
            echo "FAIL: tpm2_tools_test.sh"
        fi
    fi
else
    echo "SKIP: tpm2-tools not installed, skipping tpm2_tools_test.sh"
    SKIP=$((SKIP + 1))
fi

echo ""
echo "=== fwTPM Integration Results: $PASS passed, $FAIL failed, $SKIP skipped ==="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
