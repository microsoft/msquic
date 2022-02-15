# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    FrameTest.cpp
    PacketNumberTest.cpp
    PartitionTest.cpp
    RangeTest.cpp
    SettingsTest.cpp
    SpinFrame.cpp
    TicketTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
    VersionNegExtTest.cpp
)

add_executable(msquiccoretest ${SOURCES})

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")

target_link_libraries(msquiccoretest msquic)

if (BUILD_SHARED_LIBS)
    target_link_libraries(msquiccoretest core platform)
endif()

target_link_libraries(msquiccoretest inc gtest warnings logging base_link)

add_test(NAME msquiccoretest
         COMMAND msquiccoretest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
