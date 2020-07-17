# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

set(SOURCES
    quicmain.cpp
    ThroughputServer.cpp
    ThroughputClient.cpp
)

include_directories(${PROJECT_SOURCE_DIR}/src/test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /permissive-")
endif()

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(PERFLIB_CLOG_LIB ${SOURCES})

add_library(perflib ${SOURCES})

set_property(TARGET perflib PROPERTY FOLDER "tests")

target_compile_options(perflib PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

if (NOT MSVC)
    target_compile_options(perflib PRIVATE
        -Wno-missing-field-initializers
        -Wno-switch)
endif()

target_include_directories(perflib PUBLIC ${CMAKE_CURRENT_LIST_DIR})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(perflib MsQuicEtw)
endif()
