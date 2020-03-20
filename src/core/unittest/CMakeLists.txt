# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

include_directories(${CMAKE_SOURCE_DIR}/src/core)
include_directories(${CMAKE_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(SOURCES
    main.cpp
    PacketNumberTest.cpp
    RangeTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
)

# Allow CLOG to preprocess all the source files.
CLOG_ADD_SOURCEFILE(MSQUIC_CORETEST ${SOURCES})

add_executable(msquiccoretest ${SOURCES})

target_link_libraries(msquiccoretest msquic gtest MSQUIC_CORETEST)

add_test(msquiccoretest msquiccoretest)