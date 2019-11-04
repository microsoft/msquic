# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
    utils.c
    worker.c
)

if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(SOURCES ${SOURCES} inline.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS}")

add_library(core STATIC ${SOURCES})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(core MsQuicEtw)
endif()
