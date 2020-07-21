# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    Client.cpp
    PingConnection.cpp
    PingStream.cpp
    QuicPing.cpp
    Server.cpp
)

add_executable(quicping ${SOURCES})

set_property(TARGET quicping PROPERTY FOLDER "tools")

target_link_libraries(quicping msquic platform base)

if (NOT MSVC)
    target_compile_options(quicping PRIVATE -Wno-switch)
endif()
