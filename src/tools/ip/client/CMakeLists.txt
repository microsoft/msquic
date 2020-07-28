# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicipclient quicipclient.cpp)
quic_tool_warnings(quicipclient)

target_include_directories(quicipclient PRIVATE ${PROJECT_SOURCE_DIR}/src/tools/ip)
