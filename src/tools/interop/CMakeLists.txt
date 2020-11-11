# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Allow CLOG to preprocess all the source files.
add_clog_library(interop.clog STATIC interop.cpp)

add_quic_tool(quicinterop interop.cpp)
target_link_libraries(quicinterop interop.clog)
