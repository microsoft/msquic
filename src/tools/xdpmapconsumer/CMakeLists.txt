# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(xdpmapconsumer xdpmapconsumer.c)
quic_tool_warnings(xdpmapconsumer)

target_compile_definitions(xdpmapconsumer PRIVATE XDP_API_VERSION=3)
target_include_directories(xdpmapconsumer SYSTEM PRIVATE
    ${PROJECT_SOURCE_DIR}/submodules/xdp-for-windows/published/external)
