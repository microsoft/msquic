#!/bin/bash

# Enable core dumps.
echo "Enabling core dumps..."
ulimit -c unlimited
mkdir artifacts/dumps
cd artifacts/dumps

# Run spinquic for a while.
../linux/bin/spinquic both -timeout:300000

# Print any core files that might be generated.
echo "Available core dumps:"
ls
