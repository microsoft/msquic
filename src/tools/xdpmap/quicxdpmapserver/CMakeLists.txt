# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicxdpmapserver quicxdpmapserver.c)
quic_tool_warnings(quicxdpmapserver)

target_include_directories(quicxdpmapserver PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/..)
