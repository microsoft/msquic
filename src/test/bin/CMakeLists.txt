# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    quic_gtest.cpp
    quic_gtest.h
)

add_executable(msquictest ${SOURCES})

target_include_directories(msquictest PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

set_property(TARGET msquictest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")

target_link_libraries(msquictest msquic testlib)

if (BUILD_SHARED_LIBS)
    target_link_libraries(msquictest platform)
endif()

target_link_libraries(msquictest inc gtest logging base_link)

# At least /W3 must be used on all windows builds to pass compliance
if(MSVC)
    target_compile_options(msquictest PRIVATE /W3 /bigobj)
endif()

add_test(NAME msquictest
         COMMAND msquictest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
