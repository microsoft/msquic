# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


# Include Files that need CLOG processing
include("../../../CLog.make")
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

include_directories(${CMAKE_SOURCE_DIR}/src/test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

#
# Setup CLOG by calling a helper function which sets up dependencies.  Then add the .c file
#     ...it'd be preferred to have the helper function set this requirement
#
#CLOG_ADD_SOURCEFILE(TESTLIB_CLOG_LIB ${SOURCES})

add_library(testlib ${SOURCES})

target_compile_options(testlib PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()
