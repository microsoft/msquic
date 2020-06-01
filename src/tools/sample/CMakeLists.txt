# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(quicsample sample.cpp)
target_compile_options(quicsample PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

target_link_libraries(quicsample msquic)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicsample
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
