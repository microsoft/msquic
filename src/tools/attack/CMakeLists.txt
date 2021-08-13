# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

add_quic_tool(quicattack ${SOURCES})

target_include_directories(quicattack PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
target_link_libraries(quicattack)

if (BUILD_SHARED_LIBS)
    target_link_libraries(quicattack core platform)
endif()

target_link_libraries(quicattack logging)
