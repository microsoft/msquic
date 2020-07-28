# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

add_quic_tool(quicattack ${SOURCES})

target_include_directories(quicattack PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
target_link_libraries(quicattack core)

if (NOT MSVC)
    # This must be on the individual executables
    # CMake 3.13 is needed to solve this, but we want a minimum of 3.5
    # This will be removed with #636
    SET_TARGET_PROPERTIES(quicattack
        PROPERTIES LINK_FLAGS "-Wl,--no-as-needed")
endif()
