#!/bin/bash

# Setup logs.
echo "Making sure syslog is running..."
sudo service rsyslog start
echo "Clearing syslog file..."
sudo truncate -s 0 /var/log/syslog

# Enable core dumps.
ulimit -c unlimited
mkdir artifacts/dumps
cd artifacts/dumps

# Run the tests.
../bin/msquictest \
    --gtest_output=xml:../logs/linux-test-results.xml

# Copy logs to log folder (with correct permsissions).
echo "Copying logs..."
cd ../logs
sudo cp /var/log/syslog quic.log
sudo chmod -R 0777 .
