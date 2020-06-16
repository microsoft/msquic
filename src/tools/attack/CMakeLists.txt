# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

include_directories(${PROJECT_SOURCE_DIR}/src/core)

add_executable(quicattack ${SOURCES})

set_property(TARGET quicattack PROPERTY FOLDER "tools")

target_link_libraries(quicattack msquic core platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicattack
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
    if(QUIC_UWP_BUILD)
        target_link_libraries(quicattack OneCoreUAP)
    endif()
endif()
