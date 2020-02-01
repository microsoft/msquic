# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include Files that need CLOG processing
include("../../CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})
include_directories(${CMAKE_SOURCE_DIR}/test)
include_directories(${CMAKE_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(SOURCES
    quic_gtest.cpp
)

#
# Setup CLOG by calling a helper function which sets up dependencies.  Then add the .c file
#     ...it'd be preferred to have the helper function set this requirement
#
CLOG_ADD_SOURCEFILE(MSQUICTEST_CLOG_LIB ${SOURCES})

add_executable(msquictest ${SOURCES})

target_link_libraries(msquictest msquic testlib gtest MSQUICTEST_CLOG_LIB TESTLIB_CLOG_LIB)

add_test(msquictest msquictest)
