# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

add_executable(quicattack ${SOURCES})

set_property(TARGET quicattack PROPERTY FOLDER "tools")

target_include_directories(quicattack PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

target_link_libraries(quicattack msquic core platform)
