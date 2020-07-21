# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include(${CMAKE_CLOG_GENERATE_FILE})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /permissive-")
endif()

set(SOURCES
    main.cpp
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(PERFBIN_CLOG_LIB ${SOURCES})

add_executable(quicperf ${SOURCES})

set_property(TARGET quicperf PROPERTY FOLDER "tests")

target_link_libraries(quicperf msquic perflib platform gtest PLATFORM_CLOG_LIB PERFBIN_CLOG_LIB)
