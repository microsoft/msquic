# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    Client.cpp
    PingConnection.cpp
    PingStream.cpp
    QuicPing.cpp
    Server.cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(quicping ${SOURCES})

target_link_libraries(quicping msquic platform CORE_CLOG_LIB PLATFORM_CLOG_LIB)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicping
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
