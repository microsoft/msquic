# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    quic_gtest.cpp
    quic_gtest.h
)

# Allow CLOG to preprocess all the source files.
add_clog_library(msquictest.clog STATIC ${SOURCES})

add_executable(msquictest ${SOURCES})

target_include_directories(msquictest PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

set_property(TARGET msquictest PROPERTY FOLDER "tests")

target_link_libraries(msquictest msquic testlib platform inc gtest msquictest.clog)

add_test(NAME msquictest
         COMMAND msquictest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
