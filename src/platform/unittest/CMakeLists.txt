# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquicplatformtest PROPERTY FOLDER "tests")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(msquicplatformtest msquic platform inc gtest)
else()
    target_link_libraries(msquicplatformtest msquic platform inc gtest logging)
endif()

add_test(NAME msquicplatformtest
         COMMAND msquicplatformtest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
