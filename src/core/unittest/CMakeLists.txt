# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    FrameTest.cpp
    PacketNumberTest.cpp
    PartitionTest.cpp
    RangeTest.cpp
    SpinFrame.cpp
    TicketTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
    VersionNegExtTest.cpp
)

add_executable(msquiccoretest ${SOURCES})
target_compile_options(msquiccoretest PRIVATE ${QUIC_WARNING_FLAGS})

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "tests")

target_link_libraries(msquiccoretest msquic core platform inc gtest logging)

add_test(NAME msquiccoretest
         COMMAND msquiccoretest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
