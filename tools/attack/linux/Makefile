# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: all install

INCS = \
	-I$(QUIC_ROOT)/inc \
	-I$(QUIC_ROOT)/core

FILES = \
	../attack.cpp \
	../packet_writer.cpp

ODIR = $(QUIC_ROOT)/artifacts/linux

all:
	$(CXX) $(CXXFLAGS) $(INCS) -o $(ODIR)/quicattack $(FILES) -L$(ODIR) -Wl,-rpath=$(QUIC_ROOT)/artifacts/linux -lmsquic

install: all
