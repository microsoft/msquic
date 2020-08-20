# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    appmain.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(perfbin.clog STATIC ${SOURCES})

add_executable(quicperf ${SOURCES})

set_property(TARGET quicperf PROPERTY FOLDER "perf")

target_link_libraries(quicperf inc warnings perflib msquic platform perfbin.clog)
