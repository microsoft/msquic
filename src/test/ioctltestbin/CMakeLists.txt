# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(msquicioctltest.clog STATIC ${SOURCES})

add_executable(msquicioctltest ${SOURCES})

target_include_directories(msquicioctltest PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

set_property(TARGET msquicioctltest PROPERTY FOLDER "tests")

target_link_libraries(msquicioctltest msquic platform inc gtest msquicioctltest.clog)

add_test(NAME msquicioctltest
         COMMAND msquicioctltest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
