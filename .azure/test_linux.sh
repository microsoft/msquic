#!/bin/bash

# Setup logs.
echo "Clearing syslog file..."
sudo truncate -s 0 /var/log/syslog

# Enable core dumps.
echo "Enabling core dumps..."
ulimit -c unlimited
mkdir artifacts/dumps
cd artifacts/dumps

# Run the tests.
../linux/bin/msquictest \
    --gtest_filter=$1 \
    --gtest_output=xml:../logs/linux-test-results.xml

# Print any core files that might be generated.
echo "Available core dumps:"
ls

# Copy logs to log folder (with correct permsissions).
echo "Copying logs..."
cd ../logs
sudo cp /var/log/syslog quic.log
sudo chmod -R 0777 .
