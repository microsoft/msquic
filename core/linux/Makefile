# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

.PHONY: install all clean

INCS = -I$(QUIC_ROOT)/inc

OBJ_NAMES = \
	ack_tracker.o \
	api.o \
	binding.o \
	congestion_control.o \
	connection.o \
	crypto.o \
	crypto_tls.o \
	frame.o \
	library.o \
	listener.o \
	lookup.o \
	loss_detection.o \
	operation.o \
	packet.o \
	packet_builder.o \
	packet_space.o \
	range.o \
	recv_buffer.o \
	registration.o \
	send.o \
	send_buffer.o \
	sent_packet_metadata.o \
	session.o \
	settings.o \
	stream.o \
	stream_recv.o \
	stream_send.o \
	stream_set.o \
	timer_wheel.o \
	utils.o \
	worker.o

ODIR = $(QUIC_ROOT)/artifacts/linux/objs

OBJ = $(patsubst %,$(ODIR)/%,$(OBJ_NAMES))

$(ODIR)/%.o: ../%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCS)

all: $(OBJ)

install: all
