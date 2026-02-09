#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Runs a single Google Test executable, collecting logs and crash dumps.
# Bash replacement for run-gtest.ps1 (Linux/macOS focused).
#
# Usage:
#   ./scripts/run-gtest.sh --path <test-binary> [options]

set -euo pipefail

##############################################################################
# Defaults
##############################################################################
TEST_PATH=""
FILTER=""
LIST_TEST_CASES=0
ISOLATION_MODE="Isolated"   # Isolated | Batch
KEEP_OUTPUT_ON_SUCCESS=0
GENERATE_XML_RESULTS=0
DEBUGGER=0
INITIAL_BREAK=0
BREAK_ON_FAILURE=0
LOG_PROFILE="None"
COMPRESS_OUTPUT=0
PFX_PATH=""
AZP=0
GHA=0
ERRORS_AS_WARNINGS=0
EXTRA_ARTIFACT_DIR=""
DUONIC=0
OS_RUNNER=""
USE_QTIP=0

##############################################################################
# Parse arguments
##############################################################################
while [[ $# -gt 0 ]]; do
    case "$1" in
        --path)                  TEST_PATH="$2"; shift 2 ;;
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
        --pfx-path)              PFX_PATH="$2"; shift 2 ;;
        --azp)                   AZP=1; shift ;;
        --gha)                   GHA=1; shift ;;
        --errors-as-warnings)    ERRORS_AS_WARNINGS=1; shift ;;
        --extra-artifact-dir)    EXTRA_ARTIFACT_DIR="$2"; shift 2 ;;
        --duonic)                DUONIC=1; shift ;;
        --os-runner)             OS_RUNNER="$2"; shift 2 ;;
        --use-qtip)              USE_QTIP=1; shift ;;
        -h|--help)
            echo "Usage: $0 --path <test-binary> [options]"
            echo "  --filter <f>            gtest filter"
            echo "  --list-test-cases       list tests and exit"
            echo "  --isolation-mode <m>    Isolated (default) or Batch"
            echo "  --generate-xml-results  produce JUnit XML"
            echo "  --debugger              run under gdb"
            echo "  --break-on-failure      gtest_break_on_failure"
            echo "  --log-profile <p>       lttng log profile"
            echo "  --duonic                enable DuoNic"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$TEST_PATH" ]; then
    echo "ERROR: --path is required" >&2; exit 1
fi
if [ ! -f "$TEST_PATH" ]; then
    echo "ERROR: $TEST_PATH does not exist!" >&2; exit 1
fi

##############################################################################
# Globals
##############################################################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TEST_EXE_NAME="$(basename "$TEST_PATH")"
EXE_LOG_FOLDER="$TEST_EXE_NAME"
if [ -n "$EXTRA_ARTIFACT_DIR" ]; then
    EXE_LOG_FOLDER="${EXE_LOG_FOLDER}_${EXTRA_ARTIFACT_DIR}"
fi

TIMESTAMP="$(date '+%m.%d.%Y.%H.%M.%S')"
LOG_DIR="${ROOT_DIR}/artifacts/logs/${EXE_LOG_FOLDER}/${TIMESTAMP}"
mkdir -p "$LOG_DIR"

FINAL_RESULTS_PATH="${LOG_DIR}-results.xml"
CRASHED_COUNT=0
TESTS_FAILED=0
TEST_COUNT=0

##############################################################################
# Helpers
##############################################################################
log()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
logwrn() {
    if [ "$AZP" -eq 1 ] && [ "$ERRORS_AS_WARNINGS" -eq 0 ]; then
        echo "##vso[task.LogIssue type=warning;][$(date '+%Y-%m-%d %H:%M:%S')] $*"
    elif [ "$GHA" -eq 1 ] && [ "$ERRORS_AS_WARNINGS" -eq 0 ]; then
        echo "::warning::[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    else
        echo "WARNING: [$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
    fi
}
logerr() {
    if [ "$AZP" -eq 1 ] && [ "$ERRORS_AS_WARNINGS" -eq 0 ]; then
        echo "##vso[task.LogIssue type=error;][$(date '+%Y-%m-%d %H:%M:%S')] $*"
    elif [ "$GHA" -eq 1 ] && [ "$ERRORS_AS_WARNINGS" -eq 0 ]; then
        echo "::error::[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    else
        echo "ERROR: [$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
    fi
}

# Print backtrace from a core file using gdb (Linux) or lldb (macOS).
print_core_backtrace() {
    local core_file="$1"
    echo "=================================================================================="
    echo " $(basename "$core_file")"
    echo "=================================================================================="
    if [ "$(uname -s)" = "Darwin" ]; then
        lldb "$TEST_PATH" -c "$core_file" -b -o "bt all" 2>/dev/null || true
    else
        gdb "$TEST_PATH" "$core_file" -batch -ex "bt" -ex "quit" 2>/dev/null || true
    fi
}

##############################################################################
# Get test cases
##############################################################################
get_test_cases() {
    local args="--gtest_list_tests"
    if [ -n "$FILTER" ]; then
        args="--gtest_filter=$FILTER --gtest_list_tests"
    fi
    local output
    output="$("$TEST_PATH" $args 2>/dev/null)" || true

    local tests=()
    local group=""
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if [[ "$line" != " "* ]]; then
            group="$line"
        else
            local tc
            tc="$(echo "$line" | sed 's/#.*//' | xargs)"
            tests+=("${group}${tc}")
        fi
    done <<< "$output"
    printf '%s\n' "${tests[@]}"
}

##############################################################################
# Run a test executable
##############################################################################
run_test_executable() {
    local arguments="$1"
    local output_dir="$2"
    local exit_code=0

    if [ "$DEBUGGER" -eq 1 ]; then
        if [ "$INITIAL_BREAK" -eq 1 ]; then
            gdb --args "$TEST_PATH" $arguments
        else
            gdb -ex=r --args "$TEST_PATH" $arguments
        fi
        return 0
    fi

    local stdout_file="${output_dir}/stdout.txt"
    local stderr_file="${output_dir}/stderr.txt"

    (
        cd "$output_dir"
        ulimit -c unlimited 2>/dev/null || true
        export LSAN_OPTIONS="report_objects=1"
        export ASAN_OPTIONS="disable_coredump=0:abort_on_error=1"
        export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
        "$TEST_PATH" $arguments
    ) >"$stdout_file" 2>"$stderr_file" || exit_code=$?

    # Print stdout/stderr for diagnostics
    local stdout_txt="" stderr_txt=""
    [ -f "$stdout_file" ] && stdout_txt="$(cat "$stdout_file")"
    [ -f "$stderr_file" ] && stderr_txt="$(cat "$stderr_file")"

    local process_crashed=0
    local any_failed=0

    if [ "$exit_code" -ne 0 ]; then
        log "Process had nonzero exit code: $exit_code"
        process_crashed=1
    fi
    if echo "$stderr_txt" | grep -q "Aborted"; then
        process_crashed=1
    fi
    if echo "$stdout_txt" | grep -q '\[  FAILED  \]'; then
        any_failed=1
    fi

    # Check for core dump files
    local core_files
    core_files="$(find "$output_dir" -maxdepth 1 -name '*.core' -o -name 'core' -o -name 'core.*' 2>/dev/null)" || true
    if [ -n "$core_files" ]; then
        logwrn "Core file(s) generated"
        for cf in $core_files; do
            print_core_backtrace "$cf"
        done
        process_crashed=1
    fi

    if [ "$process_crashed" -eq 1 ]; then
        CRASHED_COUNT=$((CRASHED_COUNT + 1))
    fi

    # Output handling
    if [ "$any_failed" -eq 1 ] || [ "$process_crashed" -eq 1 ]; then
        logerr "${TEST_EXE_NAME} failed:"
        [ -n "$stdout_txt" ] && echo "$stdout_txt"
        [ -n "$stderr_txt" ] && echo "$stderr_txt"
    fi

    # Cleanup or keep
    if [ "$KEEP_OUTPUT_ON_SUCCESS" -eq 1 ] || [ "$process_crashed" -eq 1 ] || [ "$any_failed" -eq 1 ]; then
        if [ "$COMPRESS_OUTPUT" -eq 1 ]; then
            tar -czf "${output_dir}.tar.gz" -C "$(dirname "$output_dir")" "$(basename "$output_dir")"
            rm -rf "$output_dir"
        fi
    else
        rm -f "$stdout_file" "$stderr_file"
    fi

    return $exit_code
}

##############################################################################
# Build gtest arguments
##############################################################################
build_gtest_args() {
    local results_path="$1"
    local filter_arg="$2"

    local args="--gtest_catch_exceptions=0"
    [ -n "$filter_arg" ] && args+=" --gtest_filter=$filter_arg"
    args+=" --gtest_output=xml:$results_path"
    args+=" --timeout 60000"
    [ "$BREAK_ON_FAILURE" -eq 1 ] && args+=" --gtest_break_on_failure"
    [ "$DUONIC" -eq 1 ] && args+=" --duoNic"
    [ "$USE_QTIP" -eq 1 ] && args+=" --useQTIP"
    [ -n "$OS_RUNNER" ] && args+=" --osRunner=$OS_RUNNER"
    [ -n "$PFX_PATH" ] && args+=" -PfxPath:$PFX_PATH"
    echo "$args"
}

##############################################################################
# Run a single test case (Isolated mode)
##############################################################################
run_single_test() {
    local test_name="$1"
    # Sanitize name for filesystem
    local instance_name
    instance_name="$(echo "$test_name" | tr '/:*?"<>|' '_')"
    local local_log_dir="${LOG_DIR}/${instance_name}"
    mkdir -p "$local_log_dir"

    local results_path="${local_log_dir}/results.xml"
    local gtest_args
    gtest_args="$(build_gtest_args "$results_path" "$test_name")"

    local start_time
    start_time="$(date +%s)"

    local rc=0
    run_test_executable "$gtest_args" "$local_log_dir" || rc=$?

    local end_time
    end_time="$(date +%s)"
    local delta=$((end_time - start_time))

    if [ "$rc" -ne 0 ]; then
        logerr "$test_name failed (in ${delta} sec)"
    else
        log "$test_name succeeded (in ${delta} sec)"
    fi

    # Clean up log dir on success if not keeping output
    if [ "$KEEP_OUTPUT_ON_SUCCESS" -eq 0 ] && [ "$rc" -eq 0 ]; then
        rm -rf "$local_log_dir"
    fi

    return 0  # Don't fail the whole run for a single test
}

##############################################################################
# Run all tests (Batch mode)
##############################################################################
run_batch() {
    local gtest_args
    gtest_args="$(build_gtest_args "$FINAL_RESULTS_PATH" "$FILTER")"
    run_test_executable "$gtest_args" "$LOG_DIR" || true
}

##############################################################################
# Main
##############################################################################

# Query test cases
mapfile -t TEST_CASES < <(get_test_cases)
TEST_COUNT=${#TEST_CASES[@]}

if [ "$TEST_COUNT" -eq 0 ]; then
    log "$TEST_PATH (Skipped – no test cases found)"
    exit 0
fi

log "$TEST_PATH ($TEST_COUNT test case(s))"

if [ "$LIST_TEST_CASES" -eq 1 ]; then
    printf '%s\n' "${TEST_CASES[@]}"
    exit 0
fi

if [ "$ISOLATION_MODE" = "Batch" ]; then
    run_batch
else
    for ((i = 0; i < TEST_COUNT; i++)); do
        run_single_test "${TEST_CASES[$i]}"
    done
fi

# Final summary
if [ "$GENERATE_XML_RESULTS" -eq 0 ] && [ -f "$FINAL_RESULTS_PATH" ]; then
    rm -f "$FINAL_RESULTS_PATH"
fi

log "$TEST_COUNT test(s) run."
if [ "$KEEP_OUTPUT_ON_SUCCESS" -eq 1 ] || [ "$CRASHED_COUNT" -gt 0 ]; then
    log "Output can be found in $LOG_DIR"
fi
if [ "$CRASHED_COUNT" -gt 0 ]; then
    if [ "$ERRORS_AS_WARNINGS" -eq 1 ]; then
        logwrn "$CRASHED_COUNT test(s) crashed."
    else
        logerr "$CRASHED_COUNT test(s) crashed."
        exit 1
    fi
else
    # Clean up empty log dir on full success
    rmdir "$LOG_DIR" 2>/dev/null || true
fi
