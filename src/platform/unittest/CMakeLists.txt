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
CLOG_GENERATE_TARGET(msquicplatformtest.clog ${SOURCES})
CLOG_ADD_ARGS(msquicplatformtest.clog)

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquicplatformtest PROPERTY FOLDER "tests")

if (NOT MSVC)
    # This must be on the individual executables
    # CMake 3.13 is needed to solve this, but we want a minimum of 3.5
    SET_TARGET_PROPERTIES(msquicplatformtest
        PROPERTIES LINK_FLAGS "-Wl,--no-as-needed")
endif()

target_link_libraries(msquicplatformtest msquic platform inc gtest msquicplatformtest.clog)

add_test(msquicplatformtest msquicplatformtest)
