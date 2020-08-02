# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    quic_gtest.cpp
    quic_gtest.h
)

# Allow CLOG to preprocess all the source files.
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_clog_library(msquictest.clog STATIC ${SOURCES})
else()
    add_clog_library(msquictest.clog SHARED ${SOURCES})
endif()

add_executable(msquictest ${SOURCES})

target_include_directories(msquictest PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

set_property(TARGET msquictest PROPERTY FOLDER "tests")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(msquictest msquic testlib platform inc gtest)
else()
    target_link_libraries(msquictest msquic testlib platform inc gtest msquictest.clog)
endif()

add_test(msquictest msquictest)
