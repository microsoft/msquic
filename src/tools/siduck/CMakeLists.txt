# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicsiduck siduck.cpp)

set_property(TARGET quicsiduck PROPERTY FOLDER "tools")

target_link_libraries(quicsiduck msquic platform inc)
