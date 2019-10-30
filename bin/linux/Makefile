# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: install all clean

OPENSSL_LIBS = $(QUIC_ROOT)/openssl/build/lib/libssl.a $(QUIC_ROOT)/openssl/build/lib/libcrypto.a

FLAGS = -g -Wl,--no-undefined

LDFLAGS = -shared

INCS = \
	-I$(QUIC_ROOT)/core \
	-I$(QUIC_ROOT)/inc

TARGET = libmsquic

OBJ_NAMES = \
	init.o \
	inl_ext_def.o

ODIR = $(QUIC_ROOT)/artifacts/linux/objs

OBJ = $(patsubst %,$(ODIR)/%,$(OBJ_NAMES))

ALL_OBJS = $(wildcard $(ODIR)/*.o)

$(ODIR)/%.o:%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCS)

all:$(TARGET)

install:all

$(TARGET):$(OBJ)
ifneq ($(findstring QUIC_TLS_STUB,$(CFLAGS)),QUIC_TLS_STUB)
	$(CC) $(FLAGS) $(CFLAGS) $(INCS) $(LDFLAGS) -o $(QUIC_ROOT)/artifacts/linux/$(TARGET).so $(ALL_OBJS) $(OPENSSL_LIBS) -ldl -pthread
else
	$(CC) $(FLAGS) $(CFLAGS) $(INCS) $(LDFLAGS) -o $(QUIC_ROOT)/artifacts/linux/$(TARGET).so $(ALL_OBJS) -ldl -pthread
endif
	ar rcs $(QUIC_ROOT)/artifacts/linux/$(TARGET).a $(ALL_OBJS)
