# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

add_quic_tool(quicattack ${SOURCES})

target_include_directories(quicattack PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
# OK to include platform a second time, will not cause multiple link issues
target_link_libraries(quicattack core platform)
