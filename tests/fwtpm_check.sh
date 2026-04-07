#!/bin/bash
#
# fwtpm_check.sh - TPM make check entry point
#
# Handles three modes:
#   1. --enable-fwtpm --enable-swtpm: starts fwtpm_server on random port
#   2. --enable-fwtpm (TIS/SHM):      starts fwtpm_server with shared memory
#   3. --enable-swtpm (no fwtpm):     uses existing external TPM server
#
# Runs unit.test and run_examples.sh against the TPM.
# Exit: 0 = pass, 77 = skip, non-zero = fail
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

FWTPM_SERVER="$TOP_DIR/src/fwtpm/fwtpm_server"
UNIT_TEST="$TOP_DIR/tests/unit.test"
RUN_EXAMPLES="$TOP_DIR/examples/run_examples.sh"
PID_FILE="/tmp/fwtpm_check_$$.pid"

PASS=0
FAIL=0
SKIP=0
STARTED_SERVER=0
SKIP_EXAMPLES=0

# --- Helpers ---

# Wait for a TCP port to be listening
# Uses ss to check without connecting (nc -z would consume the accept slot)
wait_for_port() {
    local port="$1" timeout="${2:-500}" elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if ss -tln 2>/dev/null | grep -q ":${port} "; then
            return 0
        fi
        sleep 0.01
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Pick an available random port (returns port on stdout)
pick_available_port() {
    local port attempts=0
    while [ $attempts -lt 20 ]; do
        if command -v shuf > /dev/null 2>&1; then
            port=$(shuf -i 10000-65000 -n 1)
        else
            port=$(( (RANDOM % 55000) + 10000 ))
        fi
        if ! nc -z localhost "$port" 2>/dev/null; then
            echo "$port"
            return 0
        fi
        attempts=$((attempts + 1))
    done
    return 1
}

# --- wolfSSL dependency resolution ---

find_wolfssl_options() {
    local base="$1"
    # Check both installed prefix (include/wolfssl/) and source tree (wolfssl/)
    if [ -f "$base/include/wolfssl/options.h" ]; then
        echo "$base/include/wolfssl/options.h"
    elif [ -f "$base/wolfssl/options.h" ]; then
        echo "$base/wolfssl/options.h"
    fi
}

check_wolfssl_options() {
    local base="$1"
    local opts_file
    opts_file=$(find_wolfssl_options "$base")
    [ -n "$opts_file" ] || return 1
    grep -q "HAVE_PK_CALLBACKS" "$opts_file" && \
    grep -q "WOLFSSL_KEY_GEN" "$opts_file" && \
    grep -q "WOLFSSL_PUBLIC_MP" "$opts_file" && \
    grep -q "WC_RSA_NO_PADDING" "$opts_file"
}

ensure_wolfssl() {
    # 1. Explicit WOLFSSL_PATH from environment
    if [ -n "$WOLFSSL_PATH" ] && check_wolfssl_options "$WOLFSSL_PATH"; then
        echo "  wolfSSL: using $WOLFSSL_PATH"
        return 0
    fi

    # 2. Reuse prior /tmp build
    local src="/tmp/wolfssl-fwtpm"
    if [ -d "$src" ] && check_wolfssl_options "$src"; then
        WOLFSSL_PATH="$src"
        echo "  wolfSSL: using $WOLFSSL_PATH"
        return 0
    fi

    # 3. Clone and build to /tmp (no sudo)
    echo "  Building wolfSSL to $src"
    if [ ! -d "$src/.git" ]; then
        rm -rf "$src"
        git clone --depth 1 https://github.com/wolfssl/wolfssl.git "$src" \
            > /tmp/wolfssl-fwtpm-clone.log 2>&1 || return 1
    fi
    if ! check_wolfssl_options "$src"; then
        (cd "$src" && \
            ./autogen.sh > /dev/null 2>&1 && \
            ./configure \
                --enable-wolftpm --enable-pkcallbacks --enable-keygen \
                CFLAGS="-DWC_RSA_NO_PADDING" \
                > /tmp/wolfssl-fwtpm-configure.log 2>&1 && \
            make > /tmp/wolfssl-fwtpm-build.log 2>&1) || {
            echo "  wolfSSL build failed -- see /tmp/wolfssl-fwtpm-*.log"
            return 1
        }
    fi
    WOLFSSL_PATH="$src"
    echo "  wolfSSL: built at $WOLFSSL_PATH"
    return 0
}

# --- Cleanup ---

cleanup() {
    if [ "$STARTED_SERVER" = "1" ] && [ -f "$PID_FILE" ]; then
        local spid
        spid="$(cat "$PID_FILE")"
        kill "$spid" 2>/dev/null
        # SHM-mode server may block on sem_wait — force kill after 2s
        local i=0
        while kill -0 "$spid" 2>/dev/null && [ $i -lt 20 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        kill -9 "$spid" 2>/dev/null
        wait "$spid" 2>/dev/null
        rm -f "$PID_FILE"
        rm -f /tmp/fwtpm.shm
    fi
    rm -f /tmp/wolftpm_tls_ready_$$
}
trap cleanup EXIT

# --- Pre-flight checks ---

# Detect build options from wolftpm/options.h
IS_SWTPM_MODE=0
IS_FWTPM_MODE=0
HAS_GETENV=1
WOLFTPM_OPTIONS="$TOP_DIR/wolftpm/options.h"
if [ -f "$WOLFTPM_OPTIONS" ]; then
    if grep -q "WOLFTPM_SWTPM" "$WOLFTPM_OPTIONS"; then
        IS_SWTPM_MODE=1
    fi
    if grep -q "WOLFTPM_FWTPM_BUILD" "$WOLFTPM_OPTIONS"; then
        IS_FWTPM_MODE=1
    fi
    if grep -q "NO_GETENV" "$WOLFTPM_OPTIONS"; then
        HAS_GETENV=0
    fi
fi

# Determine mode
if [ $IS_FWTPM_MODE -eq 1 ]; then
    if [ ! -x "$FWTPM_SERVER" ]; then
        echo "fwtpm_server not built, skipping"
        exit 77
    fi
    if [ $IS_SWTPM_MODE -eq 1 ]; then
        echo "Mode: fwTPM + socket transport"
    else
        echo "Mode: fwTPM + TIS/SHM transport"
    fi
elif [ $IS_SWTPM_MODE -eq 1 ]; then
    echo "Mode: external TPM server (swtpm)"
else
    echo "No swtpm or fwtpm transport configured, skipping"
    exit 77
fi

# --- Resolve wolfSSL ---

echo "=== Resolving wolfSSL dependency ==="
if ! ensure_wolfssl; then
    echo "WARN: wolfSSL not available, TLS tests will be skipped"
    WOLFSSL_PATH=""
fi

# Check if the linked wolfSSL (system or WOLFSSL_PATH) has WC_RSA_NO_PADDING
# This is required for fwTPM RSA raw encrypt/decrypt operations
HAS_RSA_NO_PAD=0
for chk_path in "$WOLFSSL_PATH" "/usr/local"; do
    opts=$(find_wolfssl_options "$chk_path" 2>/dev/null)
    if [ -n "$opts" ] && grep -q "WC_RSA_NO_PADDING" "$opts" 2>/dev/null; then
        HAS_RSA_NO_PAD=1
        break
    fi
done
if [ $HAS_RSA_NO_PAD -eq 0 ]; then
    echo "WARN: wolfSSL missing WC_RSA_NO_PADDING — skipping example tests"
    echo "      Rebuild wolfSSL with: CFLAGS=\"-DWC_RSA_NO_PADDING\""
    echo "      fwTPM requires WC_RSA_NO_PADDING for RSA encrypt/decrypt"
    SKIP_EXAMPLES=1
fi

# --- Determine port and start/detect server ---

# Default port (honor env var override)
FWTPM_PORT="${TPM2_SWTPM_PORT:-2321}"
FWTPM_PLAT_PORT=$((FWTPM_PORT + 1))

if [ $IS_FWTPM_MODE -eq 1 ]; then
    # --- fwTPM mode: we manage the server lifecycle ---

    # Check if a server is already running (e.g. started by CI)
    if [ $IS_SWTPM_MODE -eq 1 ] && ss -tln 2>/dev/null | grep -q ":${FWTPM_PORT} "; then
        echo "Server already running on port $FWTPM_PORT"
        if [ $HAS_GETENV -eq 1 ]; then
            export TPM2_SWTPM_PORT="$FWTPM_PORT"
        fi
    else
        # Clean stale artifacts and start our own server
        rm -f "$TOP_DIR/fwtpm_nv.bin" /tmp/fwtpm.shm
        rm -f "$TOP_DIR/rsa_test_blob.raw" "$TOP_DIR/ecc_test_blob.raw" \
              "$TOP_DIR/keyblob.bin"
        rm -f "$TOP_DIR"/certs/tpm-*-cert.pem "$TOP_DIR"/certs/tpm-*-cert.csr
        rm -f "$TOP_DIR"/certs/server-*-cert.pem "$TOP_DIR"/certs/client-*-cert.pem

        killall fwtpm_server 2>/dev/null || true
        sleep 0.3

        if [ $HAS_GETENV -eq 1 ] && [ $IS_SWTPM_MODE -eq 1 ]; then
            FWTPM_PORT=$(pick_available_port)
            if [ -z "$FWTPM_PORT" ]; then
                echo "FAIL: Could not find available port"
                exit 1
            fi
            FWTPM_PLAT_PORT=$((FWTPM_PORT + 1))
            export TPM2_SWTPM_PORT="$FWTPM_PORT"
        fi

        STARTED_SERVER=1
        if [ $IS_SWTPM_MODE -eq 1 ]; then
            "$FWTPM_SERVER" --port "$FWTPM_PORT" --platform-port "$FWTPM_PLAT_PORT" \
                > /tmp/fwtpm_check_$$.log 2>&1 &
        else
            "$FWTPM_SERVER" > /tmp/fwtpm_check_$$.log 2>&1 &
        fi
        echo $! > "$PID_FILE"

        if [ $IS_SWTPM_MODE -eq 1 ]; then
            if ! wait_for_port "$FWTPM_PORT" 500; then
                echo "FAIL: fwtpm_server failed to start on port $FWTPM_PORT"
                cat /tmp/fwtpm_check_$$.log
                exit 1
            fi
            echo "fwTPM server started (pid=$(cat "$PID_FILE"), port=$FWTPM_PORT)"
        else
            # TIS/SHM mode: wait for shared memory file
            elapsed=0
            while [ ! -f /tmp/fwtpm.shm ] && [ $elapsed -lt 500 ]; do
                sleep 0.01
                elapsed=$((elapsed + 1))
            done
            if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
                echo "FAIL: fwtpm_server failed to start"
                cat /tmp/fwtpm_check_$$.log
                exit 1
            fi
            echo "fwTPM server started (pid=$(cat "$PID_FILE"), transport=SHM)"
        fi
    fi
else
    # --- swtpm-only mode: detect existing external TPM server ---

    if [ $HAS_GETENV -eq 1 ]; then
        export TPM2_SWTPM_PORT="$FWTPM_PORT"
    fi

    if ! ss -tln 2>/dev/null | grep -q ":${FWTPM_PORT} "; then
        echo "No TPM server on port $FWTPM_PORT, skipping (start one with: tpm_server &)"
        exit 77
    fi
    echo "Using external TPM server on port $FWTPM_PORT"

    # Clean stale artifacts (NV state belongs to external server, don't touch it)
    rm -f "$TOP_DIR/rsa_test_blob.raw" "$TOP_DIR/ecc_test_blob.raw" \
          "$TOP_DIR/keyblob.bin"
    rm -f "$TOP_DIR"/certs/tpm-*-cert.pem "$TOP_DIR"/certs/tpm-*-cert.csr
    rm -f "$TOP_DIR"/certs/server-*-cert.pem "$TOP_DIR"/certs/client-*-cert.pem
fi

# --- Run unit tests ---

if [ -x "$UNIT_TEST" ]; then
    echo ""
    echo "=== Running unit.test ==="
    cd "$TOP_DIR"
    if TPM2_SWTPM_PORT="$FWTPM_PORT" "$UNIT_TEST"; then
        PASS=$((PASS + 1))
        echo "PASS: unit.test"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: unit.test"
    fi
else
    echo "SKIP: unit.test not found"
    SKIP=$((SKIP + 1))
fi

# --- Run examples ---

if [ $SKIP_EXAMPLES -eq 1 ]; then
    echo "SKIP: run_examples.sh (missing WC_RSA_NO_PADDING)"
    SKIP=$((SKIP + 1))
elif [ -x "$RUN_EXAMPLES" ]; then
    echo ""
    echo "=== Running run_examples.sh ==="
    cd "$TOP_DIR"
    if WOLFSSL_PATH="$WOLFSSL_PATH" TPM2_SWTPM_PORT="$FWTPM_PORT" \
        "$RUN_EXAMPLES"; then
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

# --- Run tpm2-tools tests if available ---

# tpm2-tools tests are handled by their own CI job (fwtpm-tpm2tools)
# and scripts/tpm2_tools_test.sh. Not included in make check because
# the test script hardcodes port 2321 and we use random ports here.
echo "SKIP: tpm2-tools (run separately via scripts/tpm2_tools_test.sh)"
SKIP=$((SKIP + 1))

echo ""
echo "=== fwTPM Integration Results: $PASS passed, $FAIL failed, $SKIP skipped ==="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
