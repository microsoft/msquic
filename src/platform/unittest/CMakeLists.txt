# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# disable clang-tidy and cppcheck for this subdirectory, too many hits
set(CMAKE_CXX_CLANG_TIDY "")
set(CMAKE_C_CLANG_TIDY "")
set(CMAKE_CXX_CPPCHECK "")
set(CMAKE_C_CPPCHECK "")

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(msquicplatformtest.clog STATIC ${SOURCES})

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquicplatformtest PROPERTY FOLDER "tests")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(msquicplatformtest msquic platform inc gtest)
else()
    target_link_libraries(msquicplatformtest msquic platform inc gtest msquicplatformtest.clog)
endif()

add_test(NAME msquicplatformtest
         COMMAND msquicplatformtest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
