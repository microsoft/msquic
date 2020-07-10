# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

include_directories(${PROJECT_SOURCE_DIR}/src/test)
include_directories(${PROJECT_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(SOURCES
    quic_gtest.cpp
    quic_gtest.h
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(MSQUICTEST_CLOG_LIB ${SOURCES})

add_executable(msquictest ${SOURCES})

set_property(TARGET msquictest PROPERTY FOLDER "tests")

target_link_libraries(msquictest msquic testlib platform gtest PLATFORM_CLOG_LIB MSQUICTEST_CLOG_LIB TESTLIB_CLOG_LIB)

add_test(msquictest msquictest)
