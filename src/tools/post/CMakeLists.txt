# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    post.cpp
)

add_executable(quicpost ${SOURCES})

set_property(TARGET quicpost PROPERTY FOLDER "tools")

target_link_libraries(quicpost msquic platform base)
