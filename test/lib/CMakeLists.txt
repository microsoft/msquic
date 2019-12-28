# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


# Include Files that need CLOG processing
include("../../CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})

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

include_directories(${CMAKE_SOURCE_DIR}/test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

#
# Setup CLOG by calling a helper function which sets up dependencies.  Then add the .c file
#     ...it'd be preferred to have the helper function set this requirement
#
CLOG_ADD_SOURCEFILE(SOURCES ${SOURCES})


add_library(testlib ${SOURCES})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()

