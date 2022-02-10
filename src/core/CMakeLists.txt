# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

set(SOURCES
    ack_tracker.c
    api.c
    binding.c
    configuration.c
    congestion_control.c
    connection.c
    crypto.c
    crypto_tls.c
    cubic.c
    datagram.c
    frame.c
    library.c
    listener.c
    lookup.c
    loss_detection.c
    mtu_discovery.c
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
    version_neg.c
    operation.h
    stream.h
    connection.h
)

if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(SOURCES ${SOURCES} inline.c)
endif()

add_library(core STATIC ${SOURCES})

if(NOT QUIC_BUILD_SHARED)
    target_compile_definitions(core PUBLIC QUIC_BUILD_STATIC)
endif()

target_link_libraries(core PUBLIC inc)

target_link_libraries(core PRIVATE warnings main_binary_link_args)

set_property(TARGET core PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

if (MSVC AND NOT QUIC_ENABLE_SANITIZERS)
    target_compile_options(core PRIVATE /analyze)
endif()
