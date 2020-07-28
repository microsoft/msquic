# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicsample sample.cpp)

target_link_libraries(quicsample msquic platform base warnings)

set_property(TARGET quicsample PROPERTY FOLDER "tools")
