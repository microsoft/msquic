# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    InteropServer.cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(quicinteropserver ${SOURCES})

target_link_libraries(quicinteropserver msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicinteropserver
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
