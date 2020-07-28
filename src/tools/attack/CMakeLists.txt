# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    attack.cpp
    packet_writer.cpp
)

add_executable(quicattack ${SOURCES})

set_property(TARGET quicattack PROPERTY FOLDER "tools")

target_include_directories(quicattack PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
target_link_libraries(quicattack msquic core platform base)

if (NOT MSVC)
    # This must be on the individual executables
    # CMake 3.13 is needed to solve this, but we want a minimum of 3.5
    # This will be removed with #636
    SET_TARGET_PROPERTIES(quicattack
        PROPERTIES LINK_FLAGS "-Wl,--no-as-needed")
endif()
