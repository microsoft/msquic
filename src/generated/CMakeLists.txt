# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_library(logging_inc INTERFACE)
target_link_libraries(inc INTERFACE logging_inc)

if(QUIC_ENABLE_LOGGING)
    if(WIN32)
        target_link_libraries(inc INTERFACE MsQuicEtw_Header)
        add_library(logging INTERFACE)
    else()
        target_include_directories(logging_inc INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/common)
        target_include_directories(logging_inc INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_LTTNG_PLATFORM})
        target_include_directories(logging_inc INTERFACE ${LTTNGUST_INCLUDE_DIRS})

        add_library(logging INTERFACE)
    endif()
else()
    add_library(logging INTERFACE)
endif()
