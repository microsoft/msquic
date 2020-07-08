# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

add_executable(quicattack ${SOURCES})

set_property(TARGET quicattack PROPERTY FOLDER "tools")

target_include_directories(quicattack PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

target_link_libraries(quicattack msquic core platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(quicattack
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
    if(QUIC_UWP_BUILD)
        target_link_libraries(quicattack OneCoreUAP)
    endif()
endif()
