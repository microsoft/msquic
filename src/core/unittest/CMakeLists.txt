# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    FrameTest.cpp
    PacketNumberTest.cpp
    PartitionTest.cpp
    RangeTest.cpp
    SpinFrame.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
)

# Allow CLOG to preprocess all the source files.
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_clog_library(msquiccoretest.clog STATIC ${SOURCES})
else()
    add_clog_library(msquiccoretest.clog SHARED ${SOURCES})
endif()

add_executable(msquiccoretest ${SOURCES})

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "tests")


if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(msquiccoretest msquic core platform inc gtest)
else()
    target_link_libraries(msquiccoretest msquic core platform inc gtest msquiccoretest.clog)
endif()

add_test(msquiccoretest msquiccoretest)
