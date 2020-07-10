# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

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

target_include_directories(msquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET msquiccoretest PROPERTY FOLDER "tests")

if (NOT MSVC)
    target_compile_options(msquiccoretest PRIVATE
        -Wno-missing-field-initializers
        -Wno-unused-variable
        -Wno-write-strings)

    # This must be on the individual executables
    # CMake 3.13 is needed to solve this, but we want a minimum of 3.5
    SET_TARGET_PROPERTIES(msquiccoretest
        PROPERTIES LINK_FLAGS "-Wl,--no-as-needed")
endif()

target_link_libraries(msquiccoretest msquic core platform gtest MSQUIC_CORETEST)

add_test(msquiccoretest msquiccoretest)
