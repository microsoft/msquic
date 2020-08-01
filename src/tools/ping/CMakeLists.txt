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
include_directories(${PROJECT_SOURCE_DIR}/src/tools/upnp)

add_quic_tool(quicping ${SOURCES})

if(WIN32)
    target_link_libraries(quicping quicupnp comsuppw)
endif()
