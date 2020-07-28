# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    appmain.cpp
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(perfbin.clog ${SOURCES})

add_executable(quicperf ${SOURCES})

set_property(TARGET quicperf PROPERTY FOLDER "perf")

target_link_libraries(quicperf perflib msquic platform gtest perfbin.clog)
