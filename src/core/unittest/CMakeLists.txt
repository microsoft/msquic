# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include_directories(${CMAKE_SOURCE_DIR}/src/core)
include_directories(${CMAKE_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(
    SOURCES
    FrameTest.cpp
    PacketNumberTest.cpp
    RangeTest.cpp
    main.cpp
)

add_executable(msquiccoretest ${SOURCES})

target_link_libraries(msquiccoretest msquic gtest)

add_test(msquiccoretest msquiccoretest)