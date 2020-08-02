# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    appmain.cpp
)

# Allow CLOG to preprocess all the source files.
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_clog_library(perfbin.clog STATIC ${SOURCES})
else()
    add_clog_library(perfbin.clog SHARED ${SOURCES})
endif()

add_executable(quicperf ${SOURCES})

set_property(TARGET quicperf PROPERTY FOLDER "perf")

target_link_libraries(quicperf perflib msquic platform perfbin.clog)
