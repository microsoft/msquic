# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(recvfuzz recvfuzz.cpp)
target_include_directories(recvfuzz PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
if (BUILD_SHARED_LIBS)
    target_link_libraries(recvfuzz msquic_platform core_fuzz)
endif()
