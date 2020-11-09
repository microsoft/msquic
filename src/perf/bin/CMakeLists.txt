# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# disable clang-tidy and cppcheck for this subdirectory, too many hits
set(CMAKE_CXX_CLANG_TIDY "")
set(CMAKE_C_CLANG_TIDY "")
set(CMAKE_CXX_CPPCHECK "")
set(CMAKE_C_CPPCHECK "")

set(SOURCES
    appmain.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(perfbin.clog STATIC ${SOURCES})

add_executable(quicperf ${SOURCES} histogram/hdr_histogram.c)

set_property(TARGET quicperf PROPERTY FOLDER "perf")

target_link_libraries(quicperf inc warnings perflib msquic platform perfbin.clog)
