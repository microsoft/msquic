# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
add_clog_library(msquiccoretest.clog ${SOURCES})

add_executable(msquiccoretest ${SOURCES})

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "tests")

if (NOT MSVC)
    # This must be on the individual executables
    # CMake 3.13 is needed to solve this, but we want a minimum of 3.5
    SET_TARGET_PROPERTIES(msquiccoretest
        PROPERTIES LINK_FLAGS "-Wl,--no-as-needed")
endif()

target_link_libraries(msquiccoretest msquic core platform inc gtest msquiccoretest.clog)

add_test(msquiccoretest msquiccoretest)
