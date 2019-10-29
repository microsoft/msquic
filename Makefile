# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: install all clean openssl core platform_linux tls_stub tls_openssl bin unittest libbvt apitest

export CC = gcc

export GXX = g++

export CFLAGS = -O0 -g -DQUIC_PLATFORM_LINUX -DQUIC_EVENTS_STUB -DQUIC_LOGS_SYSLOG -fms-extensions -fPIC -Wall  -Wno-unknown-pragmas -Wno-unused-variable -Wno-unused-value

export CXXFLAGS = -std=c++0x -g -DQUIC_PLATFORM_LINUX -DQUIC_EVENTS_STUB -DQUIC_LOGS_SYSLOG -fms-extensions -fPIC -Wall  -Wno-reorder -Wno-unknown-pragmas -Wno-unused-variable -Wno-unused-value -Wno-sign-compare -Wno-format

export QUIC_ROOT=$(shell pwd)

all: directories openssl core platform_linux bin unittest libbvt apitest tool

all_with_stub: directories core platform_linux bin unittest libbvt apitest tool

clean:
	$(RM) -r artifacts/linux

openssl:
	cd openssl && ./config enable-tls1_3 --prefix=$(QUIC_ROOT)/openssl/build
	cd openssl && make -j$(nproc)
	cd openssl && make install_sw

platform_linux:
	cd platform && $(MAKE) -C linux

core:
	cd core && $(MAKE) -C linux

unittest:
	cd platform/unittest && $(MAKE) -C linux

bin:
	cd bin && $(MAKE) -C linux

libbvt:
	cd test/lib && $(MAKE) -C linux

apitest:
	cd test/bin && $(MAKE) -C linux

tool:
	cd tools/attack && $(MAKE) -C linux
	cd tools/ping && $(MAKE) -C linux

directories:
	mkdir -p artifacts
	mkdir -p artifacts/linux
	mkdir -p artifacts/linux/objs
	mkdir -p artifacts/linux/apitestobjs
	mkdir -p artifacts/linux/toolobjs
	mkdir -p artifacts/linux/testcerts

all: CFLAGS += -DQUIC_BUILD_OPENSSL

all: CXXFLAGS += -DQUIC_BUILD_OPENSSL

all_with_stub: CFLAGS += -DQUIC_TLS_STUB -DQUIC_BUILD_STUB

all_with_stub: CXXFLAGS += -DQUIC_TLS_STUB -DQUIC_BUILD_STUB

install: all

install_with_stub: all_with_stub
