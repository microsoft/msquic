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

set_property(TARGET quicetw PROPERTY FOLDER "tools")

target_compile_definitions(quicetw PRIVATE _CRT_SECURE_NO_WARNINGS)

target_link_libraries(quicetw msquic platform)
target_link_libraries(quicetw
    ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi tdh advapi32)
