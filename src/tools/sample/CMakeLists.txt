# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(quicsample sample.cpp)

target_link_libraries(quicsample msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicsample
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi)
endif()
