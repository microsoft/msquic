# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    ApiTest.cpp
    DrillDescriptor.cpp
    EventTest.cpp
    QuicDrill.cpp
    QuicTest.cpp
    TestConnection.cpp
    TestListener.cpp
    TestStream.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/src/test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_library(testlib ${SOURCES})
target_compile_options(testlib PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits -Wno-unknown-pragmas -Wno-unused-value>
     $<$<CXX_COMPILER_ID:MSVC>:
        /WX /W4 /sdl>)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()
