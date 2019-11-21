# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

message(STATUS "Source Dir: ${CMAKE_SOURCE_DIR}")
message(STATUS "Host System name: ${CMAKE_HOST_SYSTEM_NAME}")
if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    set(CMAKE_SYSTEM_VERSION 10.0.18362.0 CACHE STRING INTERNAL FORCE)
    set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION 10.0.18362.0 CACHE STRING INTERNAL FORCE)
endif()

project(msquic)

message(STATUS "System name: ${CMAKE_SYSTEM_NAME}")
message(STATUS "System version: ${CMAKE_SYSTEM_VERSION}")
message(STATUS "Platform version: ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")

enable_testing()

# Set the default TLS method for each platform.
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(QUIC_TLS "schannel" CACHE STRING "TLS Library to use")
else()
    set(QUIC_TLS "openssl" CACHE STRING "TLS Library to use")
endif()

option(QUIC_BUILD_TOOLS "Builds the tools code" ON)
option(QUIC_BUILD_TEST "Builds the test code" ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bld/obj)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/artifacts/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/artifacts/bin)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/artifacts/logs)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # Generate the MsQuicEtw header file.
    file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/bld/inc)
    file(WRITE ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.rc)
    include_directories(${CMAKE_SOURCE_DIR}/bld/inc)
    add_custom_command(
        OUTPUT ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.h
        OUTPUT ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.rc
        COMMAND mc.exe -um -h ${CMAKE_SOURCE_DIR}/bld/inc -r ${CMAKE_SOURCE_DIR}/bld/inc ${CMAKE_SOURCE_DIR}/manifest/MsQuicEtw.man)
    add_custom_target(MsQuicEtw
        DEPENDS ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.h
        DEPENDS ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.rc)

    # Custom build flags.
    set(QUIC_C_FLAGS "-DWIN32_LEAN_AND_MEAN -DSECURITY_WIN32 -DQUIC_EVENTS_MANIFEST_ETW -DQUIC_LOGS_STUB -DQUIC_NO_TAEF -DQUIC_0RTT_UNSUPPORTED /W4 /wd4100 /wd4101 /wd4189 /wd4458 /wd4459 /wd4702 /wd26451 /wd26812 /sdl /MP")
    set(QUIC_CXX_FLAGS "${QUIC_C_FLAGS}")
else()
    # Custom build flags.
    set(QUIC_C_FLAGS "-DQUIC_PLATFORM_LINUX -DQUIC_EVENTS_SYSLOG -DQUIC_LOGS_SYSLOG -fms-extensions -fPIC -Wall  -Wno-unknown-pragmas -Wno-unused-variable -Wno-unused-value -pthread")
    set(QUIC_CXX_FLAGS "-DQUIC_PLATFORM_LINUX -DQUIC_EVENTS_SYSLOG -DQUIC_LOGS_SYSLOG -fms-extensions -fPIC -Wall -Wno-reorder -Wno-unknown-pragmas -Wno-unused-variable -Wno-unused-value -Wno-sign-compare -Wno-format --std=c++17 -g -pthread")
endif()

if(QUIC_TLS STREQUAL "openssl")
    # Configure and build OpenSSL.
    add_custom_command(
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/submodules/openssl
        OUTPUT ${CMAKE_SOURCE_DIR}/bld/openssl/include
        OUTPUT ${CMAKE_SOURCE_DIR}/bld/openssl/lib/libcrypto.so
        OUTPUT ${CMAKE_SOURCE_DIR}/bld/openssl/lib/libssl.so
        COMMAND ./Configure linux-x86_64 enable-tls1_3 --prefix=${CMAKE_SOURCE_DIR}/bld/openssl
        COMMAND make -j$(nproc)
        COMMAND make install_sw)
    add_custom_target(OpenSSL
        DEPENDS ${CMAKE_SOURCE_DIR}/bld/openssl/include
        DEPENDS ${CMAKE_SOURCE_DIR}/bld/openssl/lib/libcrypto.so
        DEPENDS ${CMAKE_SOURCE_DIR}/bld/openssl/lib/libssl.so)
endif()

include_directories(${CMAKE_SOURCE_DIR}/inc)

# Product code
add_subdirectory(core)
add_subdirectory(platform)
add_subdirectory(bin)

# Tool code
if(QUIC_BUILD_TOOLS)
    add_subdirectory(tools/attack)
    add_subdirectory(tools/interop)
    add_subdirectory(tools/ping)
    add_subdirectory(tools/sample)
    add_subdirectory(tools/spin)
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        add_subdirectory(tools/etw)
    endif()
endif()

# Test code
if(QUIC_BUILD_TEST)
    # Build the googletest framework.
    set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject")
    set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest. (Projects embedding googletest may want to turn this OFF.)")
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        option(gtest_force_shared_crt "Use shared (DLL) run-time lib even when Google Test is built as static lib." ON)
    endif()
    add_subdirectory(submodules/googletest)

    add_subdirectory(test/lib)
    add_subdirectory(test/bin)
endif()
