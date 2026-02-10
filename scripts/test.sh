#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Runs the MsQuic tests – bash replacement for test.ps1.
#
# Usage:
#   ./scripts/test.sh [options]
#
# Examples:
#   ./scripts/test.sh                                    # Run all tests
#   ./scripts/test.sh --filter 'ParameterValidation*'    # Filtered
#   ./scripts/test.sh --config Release --log-profile Full.Light

set -euo pipefail

##############################################################################
# Defaults
##############################################################################
CONFIG="Debug"
ARCH=""
TLS=""
FILTER=""
LIST_TEST_CASES=0
ISOLATION_MODE="Isolated"
KEEP_OUTPUT_ON_SUCCESS=0
GENERATE_XML_RESULTS=0
DEBUGGER=0
INITIAL_BREAK=0
BREAK_ON_FAILURE=0
LOG_PROFILE="None"
COMPRESS_OUTPUT=0
NO_PROGRESS=0
AZP=0
GHA=0
SKIP_UNIT_TESTS=0
ERRORS_AS_WARNINGS=0
DUONIC=0
USE_XDP=0
USE_QTIP=0
OS_RUNNER=""
NUM_ITERATIONS=1
EXTRA_ARTIFACT_DIR=""
CODE_COVERAGE=0
COVERAGE_HTML=0
CLANG=0

##############################################################################
# Parse arguments
##############################################################################
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)                CONFIG="$2"; shift 2 ;;
        --arch)                  ARCH="$2"; shift 2 ;;
        --tls)                   TLS="$2"; shift 2 ;;
        --filter)                FILTER="$2"; shift 2 ;;
        --list-test-cases)       LIST_TEST_CASES=1; shift ;;
        --isolation-mode)        ISOLATION_MODE="$2"; shift 2 ;;
        --keep-output-on-success) KEEP_OUTPUT_ON_SUCCESS=1; shift ;;
        --generate-xml-results)  GENERATE_XML_RESULTS=1; shift ;;
        --debugger)              DEBUGGER=1; shift ;;
        --initial-break)         INITIAL_BREAK=1; shift ;;
        --break-on-failure)      BREAK_ON_FAILURE=1; shift ;;
        --log-profile)           LOG_PROFILE="$2"; shift 2 ;;
        --compress-output)       COMPRESS_OUTPUT=1; shift ;;
        --no-progress)           NO_PROGRESS=1; shift ;;
        --azp)                   AZP=1; shift ;;
        --gha)                   GHA=1; shift ;;
        --skip-unit-tests)       SKIP_UNIT_TESTS=1; shift ;;
        --errors-as-warnings)    ERRORS_AS_WARNINGS=1; shift ;;
        --duonic)                DUONIC=1; shift ;;
        --use-xdp)               USE_XDP=1; shift ;;
        --use-qtip)              USE_QTIP=1; shift ;;
        --os-runner)             OS_RUNNER="$2"; shift 2 ;;
        --num-iterations)        NUM_ITERATIONS="$2"; shift 2 ;;
        --extra-artifact-dir)    EXTRA_ARTIFACT_DIR="$2"; shift 2 ;;
        --code-coverage)         CODE_COVERAGE=1; shift ;;
        --coverage-html)         COVERAGE_HTML=1; shift ;;
        --clang)                 CLANG=1; shift ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "  --config <Debug|Release>   Build configuration (default: Debug)"
            echo "  --arch <x64|arm64|...>     CPU architecture"
            echo "  --tls <schannel|quictls|openssl>"
            echo "  --filter <gtest-filter>    Test filter"
            echo "  --list-test-cases          List tests and exit"
            echo "  --isolation-mode <mode>    Isolated (default) or Batch"
            echo "  --num-iterations <n>       Number of iterations"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

##############################################################################
# Source build config
##############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

QUIC_CONFIG="$CONFIG"
QUIC_ARCH="$ARCH"
QUIC_TLS="$TLS"
QUIC_EXTRA_ARTIFACT_DIR="$EXTRA_ARTIFACT_DIR"
export QUIC_CONFIG QUIC_ARCH QUIC_TLS QUIC_EXTRA_ARTIFACT_DIR

# shellcheck source=get-buildconfig.sh
source "${SCRIPT_DIR}/get-buildconfig.sh"

TLS="$QUIC_TLS"
ARCH="$QUIC_ARCH"
ROOT_ARTIFACT_DIR="$QUIC_ARTIFACTS_DIR"

if [ "$USE_XDP" -eq 1 ]; then
    DUONIC=1
fi

# Code coverage validation
COVERAGE_DIR=""
if [ "$CODE_COVERAGE" -eq 1 ]; then
    if [ "$DEBUGGER" -eq 1 ]; then
        echo "ERROR: --code-coverage is not supported with --debugger" >&2; exit 1
    fi
    COVERAGE_DIR="${ROOT_DIR}/artifacts/coverage"
    mkdir -p "$COVERAGE_DIR"
fi

##############################################################################
# Locate test binaries
##############################################################################
MSQUIC_TEST="${ROOT_ARTIFACT_DIR}/msquictest"
MSQUIC_CORE_TEST="${ROOT_ARTIFACT_DIR}/msquiccoretest"
MSQUIC_PLAT_TEST="${ROOT_ARTIFACT_DIR}/msquicplatformtest"

if [ ! -f "$MSQUIC_TEST" ]; then
    echo "ERROR: Build does not exist!" >&2
    echo "Run: ./scripts/build.sh --config $CONFIG --arch $ARCH --tls $TLS" >&2
    exit 1
fi

##############################################################################
# Generate test certificates if missing
##############################################################################
PFX_FILE="${ROOT_ARTIFACT_DIR}/selfsignedservercert.pfx"
if [ ! -f "$PFX_FILE" ]; then
    bash "${SCRIPT_DIR}/install-test-certificates.sh" "$PFX_FILE"
fi

##############################################################################
# Build run-gtest arguments
##############################################################################
RUN_GTEST="${SCRIPT_DIR}/run-gtest.sh"

build_run_args() {
    local test_path="$1"
    local args="--path $test_path --isolation-mode $ISOLATION_MODE"

    [ "$DUONIC" -eq 1 ]                && args+=" --duonic"
    [ -n "$FILTER" ]                    && args+=" --filter $FILTER"
    [ "$LIST_TEST_CASES" -eq 1 ]        && args+=" --list-test-cases"
    [ "$KEEP_OUTPUT_ON_SUCCESS" -eq 1 ] && args+=" --keep-output-on-success"
    [ "$GENERATE_XML_RESULTS" -eq 1 ]   && args+=" --generate-xml-results"
    [ "$DEBUGGER" -eq 1 ]               && args+=" --debugger"
    [ "$INITIAL_BREAK" -eq 1 ]          && args+=" --initial-break"
    [ "$BREAK_ON_FAILURE" -eq 1 ]       && args+=" --break-on-failure"
    [ "$LOG_PROFILE" != "None" ]        && args+=" --log-profile $LOG_PROFILE"
    [ "$COMPRESS_OUTPUT" -eq 1 ]        && args+=" --compress-output"
    [ "$AZP" -eq 1 ]                    && args+=" --azp"
    [ "$GHA" -eq 1 ]                    && args+=" --gha"
    [ "$ERRORS_AS_WARNINGS" -eq 1 ]     && args+=" --errors-as-warnings"
    [ -n "$OS_RUNNER" ]                 && args+=" --os-runner $OS_RUNNER"
    [ "$USE_QTIP" -eq 1 ]              && args+=" --use-qtip"
    [ -n "$EXTRA_ARTIFACT_DIR" ]        && args+=" --extra-artifact-dir $EXTRA_ARTIFACT_DIR"
    [ "$CODE_COVERAGE" -eq 1 ]          && args+=" --code-coverage"
    [ -f "$PFX_FILE" ]                  && args+=" --pfx-path $PFX_FILE"

    echo "$args"
}

##############################################################################
# Collect test paths
##############################################################################
TEST_PATHS=()
if [ "$SKIP_UNIT_TESTS" -eq 0 ]; then
    [ -f "$MSQUIC_PLAT_TEST" ] && TEST_PATHS+=("$MSQUIC_PLAT_TEST")
    [ -f "$MSQUIC_CORE_TEST" ] && TEST_PATHS+=("$MSQUIC_CORE_TEST")
fi
TEST_PATHS+=("$MSQUIC_TEST")

##############################################################################
# Run tests
##############################################################################
TEST_FAILURES=0
for ((iteration = 1; iteration <= NUM_ITERATIONS; iteration++)); do
    if [ "$NUM_ITERATIONS" -gt 1 ]; then
        echo "------- Iteration $iteration -------"
    fi

    for test_path in "${TEST_PATHS[@]}"; do
        if [ ! -f "$test_path" ]; then
            echo "WARNING: $test_path not found, skipping" >&2
            continue
        fi

        local_args="$(build_run_args "$test_path")"

        if [ "$USE_XDP" -eq 1 ]; then
            nofile="$(ulimit -n)"
            sudo bash -c "ulimit -n $nofile && bash $RUN_GTEST $local_args" || TEST_FAILURES=$((TEST_FAILURES + 1))
        else
            bash "$RUN_GTEST" $local_args || TEST_FAILURES=$((TEST_FAILURES + 1))
        fi
    done
done

##############################################################################
# Code coverage collection
##############################################################################
if [ "$CODE_COVERAGE" -eq 1 ]; then
    COVERAGE_OUTPUT="${COVERAGE_DIR}/msquiccoverage.xml"
    BUILD_DIR="${ROOT_DIR}/build"

    GCOVR_TOOL="gcovr"
    if [ "$CLANG" -eq 1 ]; then
        GCOVR_TOOL="gcovr --gcov-executable 'llvm-cov gcov'"
    fi

    echo "Generating code coverage report..."
    GCOVR_ARGS="-r . \
        --filter src/core --filter src/platform --filter src/bin --filter src/inc \
        --exclude src/.*/test --exclude src/.*/unittest \
        --gcov-ignore-parse-errors=negative_hits.warn_once_per_file \
        --cobertura $COVERAGE_OUTPUT"

    if [ "$COVERAGE_HTML" -eq 1 ]; then
        COVERAGE_HTML_DIR="${COVERAGE_DIR}/html"
        mkdir -p "$COVERAGE_HTML_DIR"
        GCOVR_ARGS+=" --html-details ${COVERAGE_HTML_DIR}/index.html"
    fi

    (cd "$ROOT_DIR" && $GCOVR_TOOL $GCOVR_ARGS build/) || true

    if [ -f "$COVERAGE_OUTPUT" ]; then
        echo "Coverage report (XML): $COVERAGE_OUTPUT"
    else
        echo "WARNING: No coverage results generated!" >&2
    fi
    if [ "$COVERAGE_HTML" -eq 1 ] && [ -f "${COVERAGE_HTML_DIR}/index.html" ]; then
        echo "Coverage report (HTML): ${COVERAGE_HTML_DIR}/index.html"
    fi
fi

if [ "$TEST_FAILURES" -gt 0 ]; then
    echo "WARNING: $TEST_FAILURES test binary(ies) had failures." >&2
fi
exit 0
