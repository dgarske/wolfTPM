#!/bin/bash
# fwtpm_build_test.sh
# Automated build + test cycle for fwTPM development.
# Rebuilds wolfTPM, starts fwtpm_server, runs tests, reports results.
#
# Usage:
#   scripts/fwtpm_build_test.sh [--quick] [--tpm2tools] [--all]
#
# Options:
#   --quick              Build + run_examples.sh only (fastest)
#   --tpm2tools          Build + tpm2-tools test only
#   --all                Build + run_examples.sh + make check + tpm2-tools (default)
#   --no-build           Skip build, just run tests
#   --wolfssl-path=PATH  Explicit wolfSSL install path
#
# Exit: 0 if all pass, 1 on failure

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WOLFTPM_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WOLFTPM_ROOT" || exit 1

MODE="all"
DO_BUILD=1
WOLFSSL_USER_PATH=""
WOLFSSL_CONFIGURE_ARG=""
WOLFSSL_PATH="${WOLFSSL_PATH:-../wolfssl}"

for arg in "$@"; do
    case "$arg" in
        --quick)     MODE="quick" ;;
        --tpm2tools) MODE="tpm2tools" ;;
        --all)       MODE="all" ;;
        --no-build)  DO_BUILD=0 ;;
        --wolfssl-path=*)
            WOLFSSL_USER_PATH="${arg#--wolfssl-path=}" ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -16; exit 0 ;;
    esac
done

PASS=0; FAIL=0
step() {
    printf "\033[36m[%s] %s\033[0m\n" "$(date +%H:%M:%S)" "$1"
}
pass() {
    printf "\033[32m  PASS: %s\033[0m\n" "$1"
    PASS=$((PASS+1))
}
fail() {
    printf "\033[31m  FAIL: %s\033[0m\n" "$1"
    FAIL=$((FAIL+1))
}

# --- wolfSSL dependency ---
check_wolfssl_options() {
    local base="$1"
    local opts_file="$base/include/wolfssl/options.h"
    [ -f "$opts_file" ] || return 1
    grep -q "HAVE_PK_CALLBACKS" "$opts_file" && \
    grep -q "WOLFSSL_KEY_GEN" "$opts_file" && \
    grep -q "WOLFSSL_PUBLIC_MP" "$opts_file" && \
    grep -q "WC_RSA_NO_PADDING" "$opts_file"
}

ensure_wolfssl() {
    # 1. Explicit user path
    if [ -n "$WOLFSSL_USER_PATH" ]; then
        if check_wolfssl_options "$WOLFSSL_USER_PATH"; then
            WOLFSSL_PATH="$WOLFSSL_USER_PATH"
            printf "  wolfSSL: using %s\n" "$WOLFSSL_USER_PATH"
            return 0
        else
            printf "\033[31m  wolfSSL at %s missing required options\033[0m\n" \
                "$WOLFSSL_USER_PATH"
            return 1
        fi
    fi

    # 2. System install (/usr/local)
    if check_wolfssl_options "/usr/local"; then
        # Use /tmp/wolfssl-fwtpm for WOLFSSL_PATH if it exists (has TLS examples)
        if [ -d "/tmp/wolfssl-fwtpm/examples/server" ]; then
            WOLFSSL_PATH="/tmp/wolfssl-fwtpm"
        fi
        printf "  wolfSSL: using system install, WOLFSSL_PATH=%s\n" "$WOLFSSL_PATH"
        return 0
    fi

    # 3. Adjacent ../wolfssl (built in place)
    if [ -d "$WOLFSSL_PATH" ] && check_wolfssl_options "$WOLFSSL_PATH"; then
        printf "  wolfSSL: using %s\n" "$WOLFSSL_PATH"
        return 0
    fi

    # 5. Clone and build to /tmp
    step "Building wolfSSL to /tmp/wolfssl-fwtpm"
    local src="/tmp/wolfssl-fwtpm"
    if [ ! -d "$src/.git" ]; then
        rm -rf "$src"
        git clone --depth 1 https://github.com/wolfssl/wolfssl.git "$src" \
            > /tmp/wolfssl-fwtpm-clone.log 2>&1 || return 1
    fi
    (cd "$src" && \
        ./autogen.sh > /dev/null 2>&1 && \
        ./configure \
            --enable-wolftpm --enable-pkcallbacks --enable-keygen \
            CFLAGS="-DWC_RSA_NO_PADDING" \
            > /tmp/wolfssl-fwtpm-configure.log 2>&1 && \
        make -j"$(nproc)" > /tmp/wolfssl-fwtpm-build.log 2>&1 && \
        sudo make install > /tmp/wolfssl-fwtpm-install.log 2>&1 && \
        sudo ldconfig) || {
        printf "\033[31m  wolfSSL build failed — see /tmp/wolfssl-fwtpm-*.log\033[0m\n"
        return 1
    }
    WOLFSSL_PATH="$src"
    printf "  wolfSSL: built and installed from %s\n" "$src"
    return 0
}

# --- Server lifecycle ---
cleanup() {
    if [ -f /tmp/fwtpm_bt_server.pid ]; then
        kill "$(cat /tmp/fwtpm_bt_server.pid)" 2>/dev/null || true
        rm -f /tmp/fwtpm_bt_server.pid
    fi
    # Catch any stragglers (killall matches binary name only, not script paths)
    killall fwtpm_server 2>/dev/null || true
}
trap cleanup EXIT

wait_for_server() {
    local pid=$1
    # Give the server time to bind the port
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    return 1
}

start_server() {
    # Kill any stale servers (killall matches binary name only, not script paths)
    killall fwtpm_server 2>/dev/null || true
    sleep 0.3
    rm -f fwtpm_nv.bin /tmp/fwtpm.shm
    # Clean stale key blobs and certs that depend on TPM NV state (seeds/SRK).
    # run_examples.sh regenerates these, but leftover files from a previous NV
    # session cause TLS test failures (cert doesn't match new TPM key).
    rm -f rsa_test_blob.raw ecc_test_blob.raw keyblob.bin
    rm -f ./certs/tpm-rsa-cert.pem ./certs/tpm-ecc-cert.pem
    rm -f ./certs/tpm-rsa-cert.csr ./certs/tpm-ecc-cert.csr
    rm -f ./certs/server-rsa-cert.pem ./certs/server-ecc-cert.pem
    rm -f ./certs/client-rsa-cert.pem ./certs/client-ecc-cert.pem

    src/fwtpm/fwtpm_server \
        > /tmp/fwtpm_bt_srv.log 2>&1 &
    echo $! > /tmp/fwtpm_bt_server.pid

    if wait_for_server "$(cat /tmp/fwtpm_bt_server.pid)"; then
        pass "Server started"
    else
        fail "Server failed to start"
        cat /tmp/fwtpm_bt_srv.log
        exit 1
    fi
}

# --- Resolve wolfSSL path (needed for run_examples.sh even with --no-build) ---
step "Checking wolfSSL dependency"
if ! ensure_wolfssl; then
    fail "wolfSSL dependency"
    exit 1
fi

# --- Build ---
if [ $DO_BUILD -eq 1 ]; then
    step "Building wolfTPM + fwtpm_server"
    if [ ! -f Makefile ]; then
        ./autogen.sh > /dev/null 2>&1
        ./configure --enable-fwtpm --enable-swtpm \
            $WOLFSSL_CONFIGURE_ARG > /dev/null 2>&1
    fi
    if make -j"$(nproc)" > /tmp/fwtpm_bt_build.log 2>&1; then
        pass "Build"
    else
        fail "Build"
        tail -20 /tmp/fwtpm_bt_build.log
        exit 1
    fi
fi

# --- Start server ---
step "Starting fwtpm_server"
start_server

# --- run_examples.sh ---
if [ "$MODE" = "quick" ] || [ "$MODE" = "all" ]; then
    step "Running examples (run_examples.sh)"
    if WOLFSSL_PATH="$WOLFSSL_PATH" ./examples/run_examples.sh \
        > /tmp/fwtpm_bt_examples.log 2>&1; then
        pass "run_examples.sh"
    else
        fail "run_examples.sh"
        grep "failed" /tmp/fwtpm_bt_examples.log || tail -10 /tmp/fwtpm_bt_examples.log
    fi
fi

# --- make check ---
if [ "$MODE" = "all" ]; then
    step "Running unit tests (make check)"
    if make check > /tmp/fwtpm_bt_check.log 2>&1; then
        pass "make check"
    else
        fail "make check"
        tail -10 /tmp/fwtpm_bt_check.log
    fi
fi

# --- Detect TIS/SHM mode (no TCP sockets — tpm2-tools cannot connect) ---
IS_TIS_MODE=0
if [ -f "$WOLFTPM_ROOT/wolftpm/options.h" ] && \
   grep -q "WOLFTPM_FWTPM_HAL" "$WOLFTPM_ROOT/wolftpm/options.h" && \
   ! grep -q "WOLFTPM_SWTPM" "$WOLFTPM_ROOT/wolftpm/options.h"; then
    IS_TIS_MODE=1
fi

# --- tpm2-tools ---
if [ "$MODE" = "tpm2tools" ] || [ "$MODE" = "all" ]; then
    if [ $IS_TIS_MODE -eq 1 ]; then
        printf "  \033[33mSKIP: tpm2-tools (TIS/SHM mode — no TCP sockets)\033[0m\n"
    elif command -v tpm2_startup > /dev/null 2>&1; then
        step "Running tpm2-tools tests"
        # Restart server for clean state
        cleanup
        sleep 0.3
        start_server

        if scripts/tpm2_tools_test.sh --no-start \
            > /tmp/fwtpm_bt_tpm2tools.log 2>&1; then
            TPASS=$(grep "PASS" /tmp/fwtpm_bt_tpm2tools.log | tail -1 | awk '{print $2}')
            TFAIL=$(grep "FAIL" /tmp/fwtpm_bt_tpm2tools.log | tail -1 | awk '{print $2}')
            pass "tpm2-tools ($TPASS pass, $TFAIL fail)"
        else
            fail "tpm2-tools"
            grep "\[FAIL\]" /tmp/fwtpm_bt_tpm2tools.log || \
                tail -10 /tmp/fwtpm_bt_tpm2tools.log
        fi
    else
        printf "  \033[33mSKIP: tpm2-tools not installed\033[0m\n"
    fi
fi

# --- Summary ---
printf "\n\033[36m========================================\033[0m\n"
printf "  PASS: %d  FAIL: %d\n" $PASS $FAIL
printf "\033[36m========================================\033[0m\n"

[ $FAIL -eq 0 ]
