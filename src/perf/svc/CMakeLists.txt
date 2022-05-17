# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.c
)

add_executable(secnetperfservice ${SOURCES})

set_property(TARGET secnetperfservice PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}perf")

target_link_libraries(secnetperfservice inc warnings perflib)

if (BUILD_SHARED_LIBS)
    target_link_libraries(secnetperfservice platform)
endif()

target_link_libraries(secnetperfservice logging base_link)
