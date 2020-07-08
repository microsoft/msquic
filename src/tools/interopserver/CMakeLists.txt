# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    InteropServer.cpp
)

add_executable(quicinteropserver ${SOURCES})

set_property(TARGET quicinteropserver PROPERTY FOLDER "tools")

target_link_libraries(quicinteropserver msquic platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(quicinteropserver
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
