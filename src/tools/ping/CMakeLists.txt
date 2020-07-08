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

target_link_libraries(quicping msquic platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(quicping
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
