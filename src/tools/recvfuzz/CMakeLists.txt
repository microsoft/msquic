# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if(NOT QUIC_BUILD_SHARED)
    add_compile_definitions(QUIC_BUILD_STATIC)
endif()
add_quic_tool(recvfuzz recvfuzz.cpp)
target_include_directories(recvfuzz PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
if (BUILD_SHARED_LIBS)
    target_link_libraries(recvfuzz core msquic msquic_platform)
endif()
