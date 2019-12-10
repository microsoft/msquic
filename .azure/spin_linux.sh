#!/bin/bash

# Enable core dumps.
ulimit -c unlimited
mkdir artifacts/dumps
cd artifacts/dumps

# Run spinquic for a while.
../bin/spinquic both -timeout:300000

ls