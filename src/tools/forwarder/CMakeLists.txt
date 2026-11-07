# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(quicforward forwarder.cpp)

if(QUIC_BUILD_TEST)
    add_subdirectory(test)
endif()
