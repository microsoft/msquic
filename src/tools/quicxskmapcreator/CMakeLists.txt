# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicxskmapcreator quicxskmapcreator.c)
quic_tool_warnings(quicxskmapcreator)

target_compile_definitions(quicxskmapcreator PRIVATE XDP_API_VERSION=3)
target_include_directories(quicxskmapcreator SYSTEM PRIVATE
    ${PROJECT_SOURCE_DIR}/submodules/xdp-for-windows/published/external)
