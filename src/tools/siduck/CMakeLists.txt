# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(quicsiduck siduck.cpp)

set_property(TARGET quicsiduck PROPERTY FOLDER "tools")

target_link_libraries(quicsiduck msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicsiduck
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
