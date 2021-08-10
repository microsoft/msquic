# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicinterop interop.cpp)
target_link_libraries(quicinterop logging)
