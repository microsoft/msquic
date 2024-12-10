# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.16)

project(msquic_platform_external)

find_package(msquic CONFIG REQUIRED)

message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")

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

# Remove QUIC_EVENTS_MANIFEST_ETW and QUIC_LOGS_MANIFEST_ETW definitions. These definitions for internal use in msquic
get_target_property(defs msquic::inc INTERFACE_COMPILE_DEFINITIONS)
list(FILTER defs EXCLUDE REGEX "^(QUIC_EVENTS_MANIFEST_ETW|QUIC_LOGS_MANIFEST_ETW)$")
set_target_properties(msquic::inc PROPERTIES  INTERFACE_COMPILE_DEFINITIONS "${defs}")

add_executable(msquicplatformtest ${SOURCES})
target_include_directories(msquicplatformtest PRIVATE ${CMAKE_INSTALL_PREFIX}/include)
target_link_libraries(msquicplatformtest PRIVATE gtest msquic::msquic msquic::msquic_platform ws2_32 ntdll ncrypt crypt32 iphlpapi)
target_compile_definitions(msquicplatformtest PRIVATE QUIC_EVENTS_STUB QUIC_LOGS_STUB _DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION)
