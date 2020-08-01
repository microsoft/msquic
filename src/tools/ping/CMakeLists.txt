# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    Client.cpp
    PingConnection.cpp
    PingStream.cpp
    QuicPing.cpp
    Server.cpp
)

include_directories(${PROJECT_SOURCE_DIR}/src/tools/ip)

add_quic_tool(quicping ${SOURCES})
