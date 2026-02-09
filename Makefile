# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Top-level Makefile for MsQuic. Delegates to scripts/build.sh and scripts/test.sh.
#
# Usage:
#   make                  # Debug build, auto-detect platform/TLS
#   make init             # Install deps, init submodules, generate test certs
#   make CONFIG=Release   # Release build
#   make test             # Init + build + run tests
#   make coverage         # Build with gcov, run tests, generate coverage report
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

INIT_FLAGS :=
ifneq ($(TLS),)
  INIT_FLAGS += --tls $(TLS)
endif

.PHONY: all build init test clean configure coverage

all: build

init:
	./scripts/prepare-machine.sh --for-build --for-test $(INIT_FLAGS)

build:
	./scripts/build.sh $(BUILD_FLAGS)

test: init build
	./scripts/test.sh $(TEST_FLAGS)

coverage: init
	./scripts/build.sh $(BUILD_FLAGS) --code-coverage --clean
	./scripts/test.sh $(TEST_FLAGS) --code-coverage

configure:
	./scripts/build.sh $(BUILD_FLAGS) --configure-only

clean:
	./scripts/build.sh $(BUILD_FLAGS) --clean --configure-only
