# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if(NOT QUIC_BUILD_SHARED)
    add_compile_definitions(QUIC_BUILD_STATIC)
endif()
add_quic_tool(spinquic_recv spinquic_receivepacket.cpp)
target_include_directories(spinquic_recv PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
if (BUILD_SHARED_LIBS)
    target_link_libraries(spinquic_recv core platform msquic)
endif()
