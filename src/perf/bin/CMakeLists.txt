# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    appmain.cpp
)

add_executable(quicperf ${SOURCES} histogram/hdr_histogram.c)

set_property(TARGET quicperf PROPERTY FOLDER "perf")

target_link_libraries(quicperf inc warnings perflib msquic platform logging)
