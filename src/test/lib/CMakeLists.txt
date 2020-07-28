# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include(${CMAKE_CLOG_GENERATE_FILE})

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

target_link_libraries(TESTLIB_CLOG_LIB PRIVATE inc)

add_library(testlib ${SOURCES})

target_include_directories(testlib PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

target_link_libraries(testlib PRIVATE inc warnings)

set_property(TARGET testlib PROPERTY FOLDER "tests")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()
