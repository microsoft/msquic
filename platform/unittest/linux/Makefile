# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: all install

INCS = \
	-I$(QUIC_ROOT)/inc \
	-I$(QUIC_ROOT)/core

ODIR = $(QUIC_ROOT)/artifacts/linux

all:
	$(CC) $(CFLAGS) $(INCS) -o $(ODIR)/dalunittestrunner DataPathTest.c -L$(ODIR) -Wl,-rpath=$(ODIR) -lmsquic
	$(CC) $(CFLAGS) $(INCS) -o $(ODIR)/talunittestrunner TlsTest.c -L$(ODIR) -Wl,-rpath=$(ODIR) -lmsquic

install: all
