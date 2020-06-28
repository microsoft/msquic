# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(quicreach reach.cpp)

set_property(TARGET quicreach PROPERTY FOLDER "tools")

target_link_libraries(quicreach msquic platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicreach
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
