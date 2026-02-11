#!/bin/bash
# Build with code coverage and run tests, producing a coverage XML report.
# Usage: ./scripts/make-coverage.sh <gtest_filter> [coverage_output_path]
#   gtest_filter: Google Test filter pattern (e.g. *Range*)
#   coverage_output_path: optional destination for coverage XML (default: artifacts/coverage/msquiccoverage.xml)

set -euo pipefail

FILTER="${1:?Usage: $0 <gtest_filter> [coverage_output_path]}"
COVERAGE_OUTPUT="${2:-artifacts/coverage/msquiccoverage.xml}"
COVERAGE_DEFAULT="artifacts/coverage/msquiccoverage.xml"

# 1. Build with code coverage
echo "=== Building with code coverage ==="
pwsh scripts/build.ps1 -CodeCoverage

# 2. Preview test cases
echo "=== Listing test cases matching '$FILTER' ==="
pwsh scripts/test.ps1 -CodeCoverage -Filter "$FILTER" -ListTestCases

# 3. Run tests with coverage
echo "=== Running tests with coverage ==="
pwsh scripts/test.ps1 -CodeCoverage -Filter "$FILTER"

# 4. Move coverage file if custom output path requested
if [ "$COVERAGE_OUTPUT" != "$COVERAGE_DEFAULT" ] && [ -f "$COVERAGE_DEFAULT" ]; then
    mkdir -p "$(dirname "$COVERAGE_OUTPUT")"
    cp "$COVERAGE_DEFAULT" "$COVERAGE_OUTPUT"
    echo "Coverage report copied to $COVERAGE_OUTPUT"
fi

echo "=== Done. Coverage report: $COVERAGE_OUTPUT ==="
