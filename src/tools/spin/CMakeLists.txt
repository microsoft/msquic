# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(spinquic spinquic.cpp)

target_link_libraries(spinquic msquic platform CORE_CLOG_LIB PLATFORM_CLOG_LIB MSQUICTEST_CLOG_LIB)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(spinquic
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
