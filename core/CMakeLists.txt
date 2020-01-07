# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include Files that need CLOG processing
include("../CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})

set(SOURCES
    ack_tracker.c
    api.c
    binding.c
    congestion_control.c
    connection.c
    crypto.c
    crypto_tls.c
    frame.c
    library.c
    listener.c
    lookup.c
    loss_detection.c
    operation.c
    packet.c
    packet_builder.c
    packet_space.c
    path.c
    range.c
    recv_buffer.c
    registration.c
    send.c
    send_buffer.c
    sent_packet_metadata.c
    session.c
    settings.c
    stream.c
    stream_recv.c
    stream_send.c
    stream_set.c
    timer_wheel.c
    worker.c
    operation.h
    stream.h
    connection.h
)

if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(SOURCES ${SOURCES} inline.c)
endif()

#
# Setup CLOG by calling a helper function which sets up dependencies.  Then add the .c file
#     ...it'd be preferred to have the helper function set this requirement
#
CLOG_ADD_SOURCEFILE(SOURCES ${SOURCES})
	
#
# quic_trace_lttng.h is a helper and part of QUIC convention;  explicitly add it
#
#set(SOURCES ${SOURCES} ${CMAKE_CLOG_OUTPUT_DIRECTORY}/quic_trace_lttng.h.clog.lttng.h.c)



set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS} ")

add_library(core STATIC ${SOURCES})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(core MsQuicEtw)
endif()

add_dependencies(core inc)

