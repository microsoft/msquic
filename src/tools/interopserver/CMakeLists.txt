# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    InteropServer.cpp
)

add_executable(quicinteropserver ${SOURCES})

set_property(TARGET quicinteropserver PROPERTY FOLDER "tools")

target_link_libraries(quicinteropserver msquic platform inc)
