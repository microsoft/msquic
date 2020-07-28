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

add_quic_tool(quicetw ${SOURCES})

target_compile_definitions(quicetw PRIVATE _CRT_SECURE_NO_WARNINGS)

target_link_libraries(quicetw tdh)
