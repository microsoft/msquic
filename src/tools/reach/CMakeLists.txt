# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicreach reach.cpp)

set_property(TARGET quicreach PROPERTY FOLDER "tools")

target_link_libraries(quicreach msquic platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(quicreach
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
