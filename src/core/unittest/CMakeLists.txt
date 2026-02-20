# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    CubicTest.cpp
    FrameTest.cpp
    PacketNumberTest.cpp
    PartitionTest.cpp
    RangeTest.cpp
    RecvBufferTest.cpp
    RecvBufferBenchTest.cpp
    SettingsTest.cpp
    SlidingWindowExtremumTest.cpp
    SpinFrame.cpp
    TicketTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
    VersionNegExtTest.cpp
)

# Verified recv_buffer (Karamel-extracted from Pulse)
set(VERIFIED_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../verified)
set(VERIFIED_SOURCES
    ${VERIFIED_DIR}/verified_recv_buffer.c
    ${VERIFIED_DIR}/verified_recv_buffer_rangemap.c
    ${VERIFIED_DIR}/verified_prims_support.c
    ${VERIFIED_DIR}/krmlinit.c
)
add_library(verified_recv_buffer STATIC ${VERIFIED_SOURCES})
target_include_directories(verified_recv_buffer PUBLIC
    ${VERIFIED_DIR}
    $ENV{HOME}/karamel/include
    $ENV{HOME}/karamel/krmllib/dist/minimal
)
target_compile_options(verified_recv_buffer PRIVATE -w) # suppress warnings in extracted code

add_executable(msquiccoretest ${SOURCES})

target_include_directories(msquiccoretest PRIVATE
    ${PROJECT_SOURCE_DIR}/src/core
    ${PROJECT_SOURCE_DIR}/src/core/verified
)

set_property(TARGET msquiccoretest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")
set_property(TARGET msquiccoretest APPEND PROPERTY BUILD_RPATH "$ORIGIN")

target_link_libraries(msquiccoretest msquic verified_recv_buffer)

if (BUILD_SHARED_LIBS)
    target_link_libraries(msquiccoretest core msquic_platform)
endif()

target_link_libraries(msquiccoretest inc gtest warnings logging base_link)

if (WIN32)
    target_link_libraries(msquiccoretest oldnames)
endif()

add_test(NAME msquiccoretest
         COMMAND msquiccoretest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
