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

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(TESTLIB_CLOG_LIB ${SOURCES})

add_library(testlib ${SOURCES})

target_include_directories(testlib PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

target_include_directories(testlib PRIVATE ${QUIC_INCLUDE_DIR})

target_compile_options(testlib PRIVATE ${QUIC_WARNING_FLAGS} ${QUIC_C_FLAGS})
target_compile_options(testlib PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${QUIC_CXX_FLAGS}>)
target_compile_definitions(testlib PRIVATE ${QUIC_COMMON_DEFINES})

set_property(TARGET testlib PROPERTY FOLDER "tests")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()
