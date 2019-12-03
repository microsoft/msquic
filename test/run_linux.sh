#!/bin/bash

# Setup logs.
echo "Making sure syslog is running..."
sudo service rsyslog start
echo "Clearing syslog file..."
sudo truncate -s 0 /var/log/syslog

# Run the tests.
./artifacts/bin/msquictest \
    --gtest_output=xml:artifacts/logs/linux-test-results.xml

# Copy logs to log folder (with correct permsissions).
echo "Copying logs..."
cd ./artifacts/logs
sudo cp /var/log/syslog quic.log
sudo chmod -R 0777 .
