# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if(NOT QUIC_BUILD_SHARED)
    add_compile_definitions(QUIC_BUILD_STATIC)
endif()
add_quic_tool(spinquic spinquic.cpp)
