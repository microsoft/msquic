# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    ack_tracker.c
    api.c
    binding.c
    configuration.c
    congestion_control.c
    connection.c
    crypto.c
    crypto_tls.c
    datagram.c
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

# Allow CLOG to preprocess all the source files.
add_clog_library(core.clog DYNAMIC ${SOURCES})

add_library(core STATIC ${SOURCES})

target_link_libraries(core PUBLIC core.clog inc)

target_link_libraries(core PRIVATE warnings)

set_property(TARGET core PROPERTY FOLDER "libraries")

if(WIN32)
    add_dependencies(core MsQuicEtw)
endif()
