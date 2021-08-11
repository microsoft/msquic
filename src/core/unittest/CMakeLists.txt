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
)

add_executable(msquiccoretest ${SOURCES})

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "tests")

target_link_libraries(msquiccoretest msquic core platform inc gtest logging)

# At least /W3 must be used on all windows builds to pass compliance
if(MSVC)
    target_compile_options(msquiccoretest PRIVATE /W3)
endif()

add_test(NAME msquiccoretest
         COMMAND msquiccoretest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
