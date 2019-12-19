#!/bin/bash

# Install LTTng.
echo "Installing LTTng..."
sudo apt-get install liblttng-ust-dev
sudo apt-get install lttng-tools

# Make sure syslog is started.
echo "Setting up syslog..."
sudo service rsyslog start
