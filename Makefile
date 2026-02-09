# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Top-level Makefile for MsQuic. Delegates to scripts/build.sh and scripts/test.sh.
#
# Usage:
#   make                  # Debug build, auto-detect platform/TLS
#   make CONFIG=Release   # Release build
#   make test             # Build then run tests
#   make clean            # Remove build and artifact dirs
#   make configure        # CMake configure only
#
# All variables (CONFIG, ARCH, TLS, PARALLEL, etc.) are passed through
# to the underlying scripts.

CONFIG   ?= Debug
ARCH     ?=
TLS      ?=
PARALLEL ?= 0

# Collect optional flags
BUILD_FLAGS := --config $(CONFIG)
TEST_FLAGS  := --config $(CONFIG)

ifneq ($(ARCH),)
  BUILD_FLAGS += --arch $(ARCH)
  TEST_FLAGS  += --arch $(ARCH)
endif
ifneq ($(TLS),)
  BUILD_FLAGS += --tls $(TLS)
  TEST_FLAGS  += --tls $(TLS)
endif
ifneq ($(PARALLEL),)
  BUILD_FLAGS += --parallel $(PARALLEL)
endif

.PHONY: all build test clean configure

all: build

build:
	./scripts/build.sh $(BUILD_FLAGS)

test: build
	./scripts/test.sh $(TEST_FLAGS)

configure:
	./scripts/build.sh $(BUILD_FLAGS) --configure-only

clean:
	./scripts/build.sh $(BUILD_FLAGS) --clean --configure-only
