# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    FrameTest.cpp
    PacketNumberTest.cpp
    PartitionTest.cpp
    RangeTest.cpp
    RecvBufferTest.cpp
    SettingsTest.cpp
    SlidingWindowExtremumTest.cpp
    SpinFrame.cpp
    TicketTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
    VersionNegExtTest.cpp
)

add_executable(msquiccoretest ${SOURCES})

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")
set_property(TARGET msquiccoretest APPEND PROPERTY BUILD_RPATH "$ORIGIN")

target_link_libraries(msquiccoretest msquic)

if (BUILD_SHARED_LIBS)
    target_link_libraries(msquiccoretest core msquic_platform)
endif()

target_link_libraries(msquiccoretest inc gtest warnings logging base_link)

if (WIN32)
    target_link_libraries(msquiccoretest oldnames)
    # VS2019 的编译器在 gtest 的 ASSERT_EQ 模板里会报 C4389(有符号/无符号不匹配)，
    # 配合 /WX 变成错误。这里只对测试目标禁用该警告，不改测试源码。
    target_compile_options(msquiccoretest PRIVATE /wd4389)
endif()

add_test(NAME msquiccoretest
         COMMAND msquiccoretest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
