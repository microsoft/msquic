 # Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: all install

INCS = \
	-I../ \
	-I../../ \
	-I$(QUIC_ROOT)/inc \
	-I$(QUIC_ROOT)/core

ODIR = $(QUIC_ROOT)/artifacts/linux/apitestobjs

BDIR = $(QUIC_ROOT)/artifacts/linux

OBJ_NAMES = \
	ApiTest.o \
	QuicTest.o \
	TestConnection.o \
	TestListener.o \
	TestStream.o \
	EventTest.o

OBJ = $(patsubst %,$(ODIR)/%,$(OBJ_NAMES))

$(ODIR)/%.o:../%.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(INCS)

all:$(OBJ)
	ar rcs $(BDIR)/libbvt.a $(OBJ)

install: all
