# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(msquicplatformtest.clog STATIC ${SOURCES})

target_link_libraries(msquicplatformtest.clog PRIVATE inc)

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquicplatformtest PROPERTY FOLDER "tests")

target_link_libraries(msquicplatformtest msquic platform inc gtest msquicplatformtest.clog)

add_test(msquicplatformtest msquicplatformtest)
