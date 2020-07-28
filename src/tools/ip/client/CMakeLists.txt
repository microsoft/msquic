# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicipserver quicipserver.cpp)
quic_tool_warnings(quicipserver)

target_include_directories(quicipclient PRIVATE ${PROJECT_SOURCE_DIR}/src/tools/ip)
