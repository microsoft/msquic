#!/bin/bash
set -x

# Enable core dumps.
echo "Enabling core dumps..."
ulimit -c unlimited

# Run the tests.
pwsh -NoLogo -NoProfile -NonInteractive \
    ./test.ps1 \
        -Config Debug \
        -Filter $1 \
        -Batch \
        -SaveXmlResults \
        -LogProfile Basic.Light \
        -ConvertLogs \
        -KeepLogsOnSuccess
