# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicxdpmappeer quicxdpmappeer.c)
quic_tool_warnings(quicxdpmappeer)

target_include_directories(quicxdpmappeer PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/..)
