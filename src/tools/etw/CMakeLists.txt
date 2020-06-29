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

add_executable(quicetw ${SOURCES})

target_compile_options(quicetw PRIVATE ${QUIC_C_FLAGS})
target_compile_options(quicetw PRIVATE "-D_CRT_SECURE_NO_WARNINGS")

set_property(TARGET quicetw PROPERTY FOLDER "tools")

target_link_libraries(quicetw msquic platform)
target_link_libraries(quicetw
    ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi tdh advapi32)
