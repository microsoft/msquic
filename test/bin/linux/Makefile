# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: all install

INCS = \
	-I$(QUIC_ROOT)/inc \
	-I$(QUIC_ROOT)/core \
	-I../../ \
	-I../../lib

ODIR = $(QUIC_ROOT)/artifacts/linux

OBJS = $(filter-out $(ODIR)/apitestobjs/apitestrunner.o, $(wildcard $(ODIR)/apitestobjs/*.o))

all:
	$(CXX) $(CXXFLAGS) $(INCS) -c -o $(ODIR)/apitestobjs/apitestrunner.o apitestrunner.cpp
	$(CXX) $(CXXFLAGS) $(INCS) -o $(ODIR)/apitestrunner $(OBJS) $(ODIR)/apitestobjs/apitestrunner.o -L$(ODIR) -Wl,-rpath=$(ODIR) -lmsquic

install: all
