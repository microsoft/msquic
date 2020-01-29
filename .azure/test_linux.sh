#!/bin/bash
set -x

# Enable core dumps.
echo "Enabling core dumps..."
ulimit -c unlimited

# Run the tests.
if [ $# -eq 0 ]
    pwsh -NoLogo -NoProfile -NonInteractive \
        ./test.ps1 \
            -Config Debug \
            -Batch \
            -SaveXmlResults \
            -LogProfile Basic.Light \
            -ConvertLogs \
            -KeepLogsOnSuccess
else
    pwsh -NoLogo -NoProfile -NonInteractive \
        ./test.ps1 \
            -Config Debug \
            -Filter $1 \
            -Batch \
            -SaveXmlResults \
            -LogProfile Basic.Light \
            -ConvertLogs \
            -KeepLogsOnSuccess
fi
