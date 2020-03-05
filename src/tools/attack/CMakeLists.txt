# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

include_directories(${CMAKE_SOURCE_DIR}/src/core)

add_executable(quicattack ${SOURCES})

target_link_libraries(quicattack core platform CORE_CLOG_LIB PLATFORM_CLOG_LIB)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicattack
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi)
endif()
