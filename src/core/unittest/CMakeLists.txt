# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include_directories(${CMAKE_SOURCE_DIR}/src/core)
include_directories(${CMAKE_SOURCE_DIR}/submodules/googletest/googletest/include)

# Include Files that need CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(
    SOURCES
    main.cpp
    PacketNumberTest.cpp
    RangeTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
)

#
# Setup CLOG by calling a helper function which sets up dependencies.  Then add the .c file
#     ...it'd be preferred to have the helper function set this requirement
#
CLOG_ADD_SOURCEFILE(MSQUIC_CORETEST ${SOURCES})

add_executable(msquiccoretest ${SOURCES})

target_link_libraries(msquiccoretest msquic gtest)

add_test(msquiccoretest msquiccoretest)