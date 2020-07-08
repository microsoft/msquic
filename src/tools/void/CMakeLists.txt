# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicvoidserver server.cpp)

target_link_libraries(quicvoidserver msquic platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

set_property(TARGET quicvoidserver PROPERTY FOLDER "tools")

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(quicvoidserver
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
