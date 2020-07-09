# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

include_directories(${PROJECT_SOURCE_DIR}/src/core)
include_directories(${PROJECT_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(SOURCES
    main.cpp
    FrameTest.cpp
    PacketNumberTest.cpp
    RangeTest.cpp
    SpinFrame.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(MSQUIC_CORETEST ${SOURCES})

add_executable(msquiccoretest ${SOURCES})

set_property(TARGET msquiccoretest PROPERTY FOLDER "tests")

target_link_libraries(msquiccoretest msquic core platform gtest PLATFORM_CLOG_LIB CORE_CLOG_LIB MSQUIC_CORETEST)

add_test(msquiccoretest msquiccoretest)
