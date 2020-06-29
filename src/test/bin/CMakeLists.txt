# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include_directories(${PROJECT_SOURCE_DIR}/src/test)
include_directories(${PROJECT_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_executable(msquictest quic_gtest.cpp)

set_property(TARGET msquictest PROPERTY FOLDER "tests")

target_link_libraries(msquictest msquic testlib platform gtest)

add_test(msquictest msquictest)
