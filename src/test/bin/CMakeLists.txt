# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    quic_gtest.cpp
    quic_gtest.h
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(msquictest.clog STATIC ${SOURCES})

target_link_libraries(msquictest.clog PRIVATE inc)

add_executable(msquictest ${SOURCES})

target_include_directories(msquictest PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

set_property(TARGET msquictest PROPERTY FOLDER "tests")

target_link_libraries(msquictest msquic testlib platform inc gtest msquictest.clog)

add_test(msquictest msquictest)
