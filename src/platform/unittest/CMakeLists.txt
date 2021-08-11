# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    PlatformTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(msquicplatformtest.clog STATIC ${SOURCES})

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquicplatformtest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")

target_link_libraries(msquicplatformtest msquic)

if (BUILD_SHARED_LIBS)
    target_link_libraries(msquicplatformtest platform)
endif()

target_link_libraries(msquicplatformtest msquic platform inc gtest warnings logging)

add_test(NAME msquicplatformtest
         COMMAND msquicplatformtest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
