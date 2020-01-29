#!/bin/bash

# Enable core dumps.
echo "Enabling core dumps..."
ulimit -c unlimited

# Run the tests.
pwsh -NoLogo -NoProfile -NonInteractive \
    ./test.ps1 \
        -Config Debug \
        -Batch \
        -Filter $1 \
        -SaveXmlResults \
        -LogProfile Basic.Light \
        -ConvertLogs
