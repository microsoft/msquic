# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicvoidserver server.cpp)

target_link_libraries(quicvoidserver msquic platform inc)

set_property(TARGET quicvoidserver PROPERTY FOLDER "tools")
