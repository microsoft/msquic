# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicinterop interop.cpp)

set_property(TARGET quicinterop PROPERTY FOLDER "tools")

target_link_libraries(quicinterop msquic platform base)
