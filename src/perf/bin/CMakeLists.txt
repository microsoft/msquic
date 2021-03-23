# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    appmain.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(perfbin.clog STATIC ${SOURCES})

add_executable(secnetperf ${SOURCES} histogram/hdr_histogram.c)

set_property(TARGET secnetperf PROPERTY FOLDER "perf")

target_link_libraries(secnetperf inc warnings perflib msquic platform perfbin.clog)
