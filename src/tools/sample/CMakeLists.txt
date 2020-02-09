# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(quicsample sample.cpp)
target_compile_options(quicsample PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits -Wno-unknown-pragmas -Wno-unused-value>
     $<$<CXX_COMPILER_ID:MSVC>:
        /WX /W4 /sdl>)

target_link_libraries(quicsample msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicsample
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi)
endif()
