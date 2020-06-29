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

target_compile_options(quicping PRIVATE ${QUIC_CXX_FLAGS})

set_property(TARGET quicping PROPERTY FOLDER "tools")

target_link_libraries(quicping msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicping
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
