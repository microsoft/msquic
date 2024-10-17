# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.16)

project(msquic_platform_external)

find_package(msquic REQUIRED)
find_library(MSPLATFORM_LIBRARIES
             NAMES msquic_platform)
find_library(GTEST_LIBRARIES 
            NAMES gtest
            PATHS ${CMAKE_INSTALL_PREFIX}/lib
            )
message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "MSPLATFORM_LIBRARIES: ${MSPLATFORM_LIBRARIES}")
message(STATUS "GTEST_LIBRARIES: ${GTEST_LIBRARIES}")

set(SOURCES
    ../main.cpp
    # ../CryptTest.cpp
    # ../DataPathTest.cpp
    # ../PlatformTest.cpp
    # ../StorageTest.cpp
    ../TlsTest.cpp
)

add_executable(msquicplatformtest ${SOURCES})

target_include_directories(msquicplatformtest PRIVATE ${CMAKE_INSTALL_PREFIX}/include)
target_link_libraries(msquicplatformtest msquic ${MSPLATFORM_LIBRARIES} ${GTEST_LIBRARIES} ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32 winmm secur32 clang_rt.asan_dbg_dynamic-x86_64 clang_rt.asan_dynamic-x86_64)
target_compile_definitions(msquicplatformtest PRIVATE QUIC_EVENTS_STUB QUIC_LOGS_STUB)
