# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include Files that need CLOG processing
include("../CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})

CLOG_ADD_SOURCEFILE(SOURCES quic_trace_lttng.h)

add_custom_target(inc
    DEPENDS ${CMAKE_CLOG_OUTPUT_DIRECTORY}/quic_trace_lttng.h.clog
)