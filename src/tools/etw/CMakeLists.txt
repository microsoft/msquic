# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    binding.c
    cxn.c
    library.c
    listener.c
    main.c
    session.c
    stream.c
    trace.c
    worker.c
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS} -D_CRT_SECURE_NO_WARNINGS")

add_executable(quicetw ${SOURCES})

target_link_libraries(quicetw msquic platform)
target_link_libraries(quicetw
    ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi tdh advapi32)