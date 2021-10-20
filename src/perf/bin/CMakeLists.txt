# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    appmain.cpp
)

add_executable(secnetperf ${SOURCES} histogram/hdr_histogram.c)

set_property(TARGET secnetperf PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}perf")

target_link_libraries(secnetperf inc warnings perflib msquic)

if (BUILD_SHARED_LIBS)
    target_link_libraries(secnetperf platform)
endif()

target_link_libraries(secnetperf logging base_link)
