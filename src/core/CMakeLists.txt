# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

find_program(CLANGTIDY NAMES clang-tidy)
if(CLANGTIDY)
    message(STATUS "Found clang-tidy: ${CLANGTIDY}")
    set(CLANG_TIDY_CHECKS *
        # add checks to ignore here, e.g.,
        # -hicpp-no-assembler
        # -hicpp-signed-bitwise
        # ...
        -cppcoreguidelines-init-variables
        -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling
        -google-readability-todo
        -hicpp-signed-bitwise
        -cppcoreguidelines-avoid-magic-numbers
        -readability-magic-numbers
        -readability-isolate-declaration
        -bugprone-sizeof-expression
        -misc-no-recursion # do you really need recursion?
        -cppcoreguidelines-avoid-non-const-global-variables
        -readability-avoid-const-params-in-decls
        -llvmlibc-restrict-system-libc-headers
    )
    string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS}")
    set(CMAKE_C_CLANG_TIDY ${CLANGTIDY} -checks=${CLANG_TIDY_CHECKS}
        -system-headers)
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY})
else()
    message(STATUS "clang-tidy not found")
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
