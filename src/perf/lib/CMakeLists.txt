# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    HpsClient.cpp
    PerfServer.cpp
    quicmain.cpp
    RpsClient.cpp
    ThroughputClient.cpp
)

# Allow CLOG to preprocess all the source files.
add_clog_library(perflib.clog STATIC ${SOURCES} PerfHelpers.h)

add_library(perflib ${SOURCES})

set_property(TARGET perflib PROPERTY FOLDER "perf")

target_link_libraries(perflib PUBLIC perflib.clog)

target_link_libraries(perflib PRIVATE inc warnings)

target_include_directories(perflib PUBLIC ${CMAKE_CURRENT_LIST_DIR})

if (MSVC)
    target_compile_options(perflib PUBLIC /wd4459)
endif()

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(perflib MsQuicEtw)
endif()
