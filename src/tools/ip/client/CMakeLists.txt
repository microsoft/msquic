# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

include_directories(${PROJECT_SOURCE_DIR}/src/tools/ip)

add_executable(quicipclient quicipclient.cpp)
target_compile_options(quicipclient PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

target_link_libraries(quicipclient msquic)

set_property(TARGET quicipclient PROPERTY FOLDER "tools")
