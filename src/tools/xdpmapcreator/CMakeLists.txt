# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(xdpmapcreator xdpmapcreator.c)
quic_tool_warnings(xdpmapcreator)

target_compile_definitions(xdpmapcreator PRIVATE XDP_API_VERSION=3)
target_include_directories(xdpmapcreator SYSTEM PRIVATE
    ${PROJECT_SOURCE_DIR}/submodules/xdp-for-windows/published/external)
