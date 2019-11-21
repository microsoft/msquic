# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    DrillDescriptor.cpp
    ApiTest.cpp
    QuicDrill.cpp
    QuicTest.cpp
    TestConnection.cpp
    TestListener.cpp
    TestStream.cpp
    EventTest.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_library(testlib ${SOURCES})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()
