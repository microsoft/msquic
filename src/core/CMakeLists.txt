# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

set(SOURCES
    ack_tracker.c
    api.c
    binding.c
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

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(CORE_CLOG_LIB ${SOURCES})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS}")

add_library(core STATIC ${SOURCES})

set_property(TARGET core PROPERTY FOLDER "libraries")

target_compile_options(core PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(core MsQuicEtw)
endif()
