# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

include_directories(${CMAKE_SOURCE_DIR}/src/test)
include_directories(${CMAKE_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(SOURCES
    quic_gtest.cpp
    quic_gtest.h
)

# Allow CLOG to preprocess all the source files.
CLOG_ADD_SOURCEFILE(MSQUICTEST_CLOG_LIB ${SOURCES})

add_executable(msquictest ${SOURCES})

target_link_libraries(msquictest msquic testlib gtest TESTLIB_CLOG_LIB)

add_test(msquictest msquictest)
