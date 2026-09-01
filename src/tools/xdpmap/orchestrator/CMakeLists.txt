# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(orchestrator orchestrator.c)
quic_tool_warnings(orchestrator)

target_compile_definitions(orchestrator PRIVATE XDP_API_VERSION=3)
target_include_directories(orchestrator PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_include_directories(orchestrator SYSTEM PRIVATE
    ${PROJECT_SOURCE_DIR}/submodules/xdp-for-windows/published/external)
