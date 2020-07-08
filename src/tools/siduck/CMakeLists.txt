# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicsiduck siduck.cpp)

set_property(TARGET quicsiduck PROPERTY FOLDER "tools")

target_link_libraries(quicsiduck msquic platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(quicsiduck
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
