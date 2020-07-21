# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicipserver quicipserver.cpp)

target_link_libraries(quicipserver msquic platform base)

set_property(TARGET quicipserver PROPERTY FOLDER "tools")
