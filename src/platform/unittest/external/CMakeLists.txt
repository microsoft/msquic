# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.16)

project(msquic_platform_external)

find_package(msquic REQUIRED)
find_library(MSPLATFORM_LIBRARIES
             NAMES msquic_platform)

message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "MSPLATFORM_LIBRARIES: ${MSPLATFORM_LIBRARIES}")

include(FetchContent)
FetchContent_Declare(
    googletest
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../submodules/googletest
)
FetchContent_MakeAvailable(googletest)

set(SOURCES
    ../main.cpp
    ../CryptTest.cpp
    ../DataPathTest.cpp
    ../PlatformTest.cpp
    # ../StorageTest.cpp
    ../TlsTest.cpp
)

if(QUIC_TLS STREQUAL "openssl" OR  QUIC_TLS STREQUAL "openssl3")
    list(APPEND OTHER_TERGETS OpenSSL)
endif()

add_executable(msquicplatformtest ${SOURCES})
target_include_directories(msquicplatformtest PRIVATE ${CMAKE_INSTALL_PREFIX}/include)
target_link_libraries(msquicplatformtest PRIVATE msquic ${MSPLATFORM_LIBRARIES} ${OTHER_TERGETS} gtest ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32 secur32 userenv onecore winmm wbemuuid clang_rt.asan_dbg_dynamic-x86_64 clang_rt.asan_dynamic-x86_64)
target_compile_definitions(msquicplatformtest PRIVATE QUIC_EVENTS_STUB QUIC_LOGS_STUB _DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION)
