# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    InteropServer.cpp
)

add_executable(quicinteropserver ${SOURCES})

target_compile_options(quicinteropserver PRIVATE ${QUIC_CXX_FLAGS})

set_property(TARGET quicinteropserver PROPERTY FOLDER "tools")

target_link_libraries(quicinteropserver msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicinteropserver
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
