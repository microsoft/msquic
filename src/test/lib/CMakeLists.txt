# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

set(SOURCES
    ApiTest.cpp
    BasicTest.cpp
    DatagramTest.cpp
    DataTest.cpp
    DrillDescriptor.cpp
    EventTest.cpp
    HandshakeTest.cpp
    QuicDrill.cpp
    TestConnection.cpp
    TestListener.cpp
    TestStream.cpp
    TestHelpers.h
)

include_directories(${PROJECT_SOURCE_DIR}/src/test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(TESTLIB_CLOG_LIB ${SOURCES})

add_library(testlib ${SOURCES})

set_property(TARGET testlib PROPERTY FOLDER "tests")

target_compile_options(testlib PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()
