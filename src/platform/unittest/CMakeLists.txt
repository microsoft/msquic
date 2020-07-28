# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include(${CMAKE_CLOG_GENERATE_FILE})

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(MSQUIC_PLATFORMTEST ${SOURCES})

target_link_libraries(MSQUIC_PLATFORMTEST PRIVATE base)

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquicplatformtest PROPERTY FOLDER "tests")

if (NOT MSVC)
    # This must be on the individual executables
    # CMake 3.13 is needed to solve this, but we want a minimum of 3.5
    SET_TARGET_PROPERTIES(msquicplatformtest
        PROPERTIES LINK_FLAGS "-Wl,--no-as-needed")
endif()

target_link_libraries(msquicplatformtest msquic platform base gtest MSQUIC_PLATFORMTEST)

add_test(msquicplatformtest msquicplatformtest)
