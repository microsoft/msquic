#!/bin/bash

# Enable core dumps.
echo "Enabling core dumps..."
ulimit -c unlimited

# Run the tests.
pwsh -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Unrestricted ./test.ps1 -Batch -SaveXmlResults -LogProfile Full.Light -ConvertLogs -Filter $1
