#!/bin/bash
# Helper functions for functional tests
# Inspired by iproute2's testsuite

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Find binaries - use from target/release or target/debug
find_binary() {
    local name="$1"
    local bin

    # Check if explicitly set
    if [ -n "${!name}" ]; then
        echo "${!name}"
        return
    fi

    # Try release first, then debug
    for dir in target/release target/debug; do
        bin="$SCRIPT_DIR/../../$dir/$name"
        if [ -x "$bin" ]; then
            echo "$bin"
            return
        fi
    done

    # Fall back to PATH
    which "$name" 2>/dev/null
}

# Initialize test environment
init_tests() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Find our binaries
    RIP_IP="${RIP_IP:-$(find_binary ip)}"
    RIP_TC="${RIP_TC:-$(find_binary tc)}"

    if [ ! -x "$RIP_IP" ]; then
        echo "Error: ip binary not found. Run 'cargo build --release' first."
        exit 1
    fi

    if [ ! -x "$RIP_TC" ]; then
        echo "Error: tc binary not found. Run 'cargo build --release' first."
        exit 1
    fi

    # Temp files for output capture
    STDOUT_TMP=$(mktemp)
    STDERR_TMP=$(mktemp)

    trap cleanup EXIT
}

# Cleanup on exit
cleanup() {
    rm -f "$STDOUT_TMP" "$STDERR_TMP"
}

# Generate random device name
rand_dev() {
    local rnd=""
    while [ ${#rnd} -ne 6 ]; do
        rnd="$(head -c 250 /dev/urandom | tr -dc '[:alpha:]' | head -c 6)"
    done
    echo "test-$rnd"
}

# Run ip command
rip_ip() {
    "$RIP_IP" "$@" >"$STDOUT_TMP" 2>"$STDERR_TMP"
    return $?
}

# Run tc command
rip_tc() {
    "$RIP_TC" "$@" >"$STDOUT_TMP" 2>"$STDERR_TMP"
    return $?
}

# Get stdout from last command
get_stdout() {
    cat "$STDOUT_TMP"
}

# Get stderr from last command
get_stderr() {
    cat "$STDERR_TMP"
}

# Log a message
log() {
    echo "$@"
}

# Test assertion: command succeeded
test_ok() {
    local desc="$1"
    local ret=$?
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ $ret -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc (exit code: $ret)"
        if [ -s "$STDERR_TMP" ]; then
            echo "  stderr: $(cat "$STDERR_TMP")"
        fi
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test assertion: command failed
test_fail() {
    local desc="$1"
    local ret=$?
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ $ret -ne 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $desc (expected failure)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc (expected failure, got success)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test assertion: output contains pattern
test_output_contains() {
    local pattern="$1"
    local desc="${2:-output contains '$pattern'}"
    TESTS_RUN=$((TESTS_RUN + 1))

    if grep -qE "$pattern" "$STDOUT_TMP"; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc"
        echo "  expected pattern: $pattern"
        echo "  actual output: $(cat "$STDOUT_TMP")"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test assertion: output does NOT contain pattern
test_output_not_contains() {
    local pattern="$1"
    local desc="${2:-output does not contain '$pattern'}"
    TESTS_RUN=$((TESTS_RUN + 1))

    if ! grep -qE "$pattern" "$STDOUT_TMP"; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc"
        echo "  unexpected pattern found: $pattern"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test assertion: output has N lines
test_output_lines() {
    local expected="$1"
    local desc="${2:-output has $expected lines}"
    local actual=$(wc -l < "$STDOUT_TMP")
    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$actual" -eq "$expected" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc (got $actual lines)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test assertion: JSON output is valid
test_json_valid() {
    local desc="${1:-JSON output is valid}"
    TESTS_RUN=$((TESTS_RUN + 1))

    if jq . "$STDOUT_TMP" >/dev/null 2>&1; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc"
        echo "  output: $(cat "$STDOUT_TMP")"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Skip a test
skip_test() {
    local desc="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    echo -e "${YELLOW}[SKIP]${NC} $desc"
}

# Check if running as root
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This test requires root privileges. Run with sudo or in a namespace."
        exit 127
    fi
}

# Print test summary
print_summary() {
    echo ""
    echo "========================================="
    echo "Test Summary"
    echo "========================================="
    echo "  Total:   $TESTS_RUN"
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo "========================================="

    if [ $TESTS_FAILED -gt 0 ]; then
        exit 1
    fi
    exit 0
}
