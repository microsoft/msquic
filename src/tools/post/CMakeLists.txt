# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    post.cpp
)

add_executable(quicpost ${SOURCES})

set_property(TARGET quicpost PROPERTY FOLDER "tools")

target_link_libraries(quicpost msquic platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(quicpost
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
