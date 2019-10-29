# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: all clean

INCS = \
	-I../ \
	-I$(QUIC_ROOT)/inc \
	-I$(QUIC_ROOT)/core \
	-I$(QUIC_ROOT)/openssl/build/include

OBJ_NAMES = \
	cert_stub.o \
	datapath_linux.o \
	hashtable.o \
	platform_linux.o \
	selfsign_openssl.o \
	selfsign_stub.o \
	storage_linux.o \
	tls_openssl.o \
	tls_stub.o

ODIR =$(QUIC_ROOT)/artifacts/linux/objs

OBJ = $(patsubst %,$(ODIR)/%,$(OBJ_NAMES))

$(ODIR)/%.o: ../%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCS)

all: $(OBJ)

install: all
