# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    HpsClient.cpp
    PerfServer.cpp
    quicmain.cpp
    RpsClient.cpp
    Tcp.cpp
    ThroughputClient.cpp
)

add_library(perflib ${SOURCES})

set_property(TARGET perflib PROPERTY FOLDER "perf")

target_link_libraries(perflib PRIVATE inc warnings)

target_include_directories(perflib PUBLIC ${CMAKE_CURRENT_LIST_DIR})

if (MSVC)
    target_compile_options(perflib PUBLIC /wd4459)
endif()
