# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: all install

INCS = -I$(QUIC_ROOT)/inc

FILES = \
	../Client.cpp \
	../PingConnection.cpp \
	../PingStream.cpp \
	../QuicPing.cpp \
	../Server.cpp

ODIR = $(QUIC_ROOT)/artifacts/linux

all:
	$(CXX) $(CXXFLAGS) $(INCS) $(FILES) -o $(ODIR)/quicping -L$(ODIR) -Wl,-rpath=$(ODIR) -lmsquic

install: all
