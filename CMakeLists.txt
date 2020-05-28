# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

message(STATUS "Source Dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Host System name: ${CMAKE_HOST_SYSTEM_NAME}")
if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    set(CMAKE_SYSTEM_VERSION 10.0.18362.0 CACHE STRING INTERNAL FORCE)
    set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION 10.0.18362.0 CACHE STRING INTERNAL FORCE)
endif()

if (QUIC_TLS STREQUAL "mitls")
    message(WARNING "Policy 0091 unsupported for miTLS.")
else()
    if(POLICY CMP0091)
        cmake_policy(SET CMP0091 NEW)
        message(STATUS "Setting policy 0091")
    else()
        message(WARNING "CMake version too old to support Policy 0091; CRT static linking won't work")
    endif()
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
option(QUIC_ENABLE_LOGGING "Enables logging" ON)
option(QUIC_SANITIZE_ADDRESS "Enables address sanitizer" OFF)
option(QUIC_STATIC_LINK_CRT "Statically links the C runtime" ON)
option(QUIC_PGO "Enables profile guided optimizations" OFF)

if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    set(QUIC_PLATFORM "windows")
else()
    set(QUIC_PLATFORM "linux")
endif()

set(QUIC_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(QUIC_OUTPUT_DIR ${QUIC_BUILD_DIR}/bin/$<IF:$<CONFIG:Debug>,Debug,Release> CACHE STRING "Output directory for build artifacts")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${QUIC_BUILD_DIR}/obj/$<IF:$<CONFIG:Debug>,Debug,Release>)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${QUIC_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${QUIC_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${QUIC_OUTPUT_DIR})

set(CLANG_GCC_WARNING_FLAGS -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits -Wno-unknown-pragmas -Wno-unused-value CACHE INTERNAL "")
set(MSVC_WARNING_FLAGS /WX /W4 /sdl CACHE INTERNAL "")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # Generate the MsQuicEtw header file.
    file(MAKE_DIRECTORY ${QUIC_BUILD_DIR}/inc)
    file(WRITE ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)
    include_directories(${QUIC_BUILD_DIR}/inc)
    add_custom_command(
        OUTPUT ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h
        OUTPUT ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc
        COMMAND mc.exe -um -h ${QUIC_BUILD_DIR}/inc -r ${QUIC_BUILD_DIR}/inc ${CMAKE_CURRENT_SOURCE_DIR}/src/manifest/MsQuicEtw.man)
    add_custom_target(MsQuicEtw
        DEPENDS ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h
        DEPENDS ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)

    # Custom build flags.
    set(QUIC_COMMON_FLAGS "-DWIN32_LEAN_AND_MEAN -DSECURITY_WIN32 /MP")
    if(QUIC_ENABLE_LOGGING)
        message(STATUS "Configuring for manifested ETW events and logging")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_EVENTS_MANIFEST_ETW -DQUIC_LOGS_MANIFEST_ETW")
    else()
        message(STATUS "Disabling events and logging")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_EVENTS_STUB -DQUIC_LOGS_STUB")
    endif()

    if(QUIC_TLS STREQUAL "openssl")
        # OpenSSL doesn't support session resumption yet.
        message(STATUS "Disabling session resumption support")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_DISABLE_RESUMPTION")
    endif()

    if(QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "schannel")
        # OpenSSL and SChannel don't support 0-RTT yet.
        message(STATUS "Disabling 0-RTT support")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_DISABLE_0RTT_TESTS")
    endif()

    if(QUIC_TLS STREQUAL "stub")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_TLS_STUB")
    endif()

    if(QUIC_SANITIZE_ADDRESS)
        message(STATUS "Address sanitizer unsupported on this platform.")
    endif()

    set(QUIC_C_FLAGS "${QUIC_COMMON_FLAGS}")
    set(QUIC_CXX_FLAGS "${QUIC_COMMON_FLAGS} /std:c++17 /EHsc")

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /USERPROFILE:PGD=${CMAKE_CURRENT_SOURCE_DIR}/src/bin/winuser/msquic.pgd /DEBUG /OPT:REF /OPT:ICF")
    if(QUIC_PGO)
        set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /GENPROFILE")
    endif()
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /DEBUG /OPT:REF /OPT:ICF")
    if(QUIC_STATIC_LINK_CRT)
        message(STATUS "Configuring for statically-linked CRT")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

else()
    # Custom build flags.
    set(QUIC_COMMON_FLAGS "-DQUIC_PLATFORM_LINUX -fms-extensions -fPIC -pthread -Wl,--no-as-needed -ldl")

    #if(QUIC_TLS STREQUAL "x64")
    #    set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -m64")
    #else()
    #    set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -m32")
    #endif()

    if(QUIC_ENABLE_LOGGING)
        include(FindLTTngUST)
        message(STATUS "Configuring for LTTng events and disabling logging")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_EVENTS_LTTNG -DQUIC_LOGS_STUB")
    else()
        message(STATUS "Disabling events and logging")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_EVENTS_STUB -DQUIC_LOGS_STUB")
        list(APPEND CLANG_GCC_WARNING_FLAGS -Wno-unused-parameter -Wno-unused-variable)
    endif()

    if(QUIC_TLS STREQUAL "openssl")
        # OpenSSL doesn't support session resumption yet.
        message(STATUS "Disabling session resumption support")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_DISABLE_RESUMPTION")
        # OpenSSL doesn't support 0-RTT yet.
        message(STATUS "Disabling 0-RTT support")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_DISABLE_0RTT_TESTS")
    endif()

    if(QUIC_SANITIZE_ADDRESS)
        message(STATUS "Configuring address sanitizer")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -fsanitize=address -fno-omit-frame-pointer -Wno-maybe-uninitialized -O0 -Og -g")
    endif()

    if(QUIC_TLS STREQUAL "stub")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_TLS_STUB")
    endif()

    set(QUIC_C_FLAGS "${QUIC_COMMON_FLAGS}")
    set(QUIC_CXX_FLAGS "${QUIC_COMMON_FLAGS} --std=c++17 -g -Wno-reorder -Wno-sign-compare -Wno-format")
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/inc)

if(QUIC_TLS STREQUAL "openssl")
    # Configure and build OpenSSL.
    add_custom_command(
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl
        OUTPUT ${QUIC_BUILD_DIR}/openssl/include
        OUTPUT ${QUIC_BUILD_DIR}/openssl/lib/libcrypto.so
        OUTPUT ${QUIC_BUILD_DIR}/openssl/lib/libssl.so
        COMMAND ./Configure linux-x86_64 enable-tls1_3 --prefix=${QUIC_BUILD_DIR}/openssl
        COMMAND make -j$$(nproc)
        COMMAND make install_sw)
    add_custom_target(OpenSSL
        DEPENDS ${QUIC_BUILD_DIR}/openssl/include
        DEPENDS ${QUIC_BUILD_DIR}/openssl/lib/libcrypto.so
        DEPENDS ${QUIC_BUILD_DIR}/openssl/lib/libssl.so)
endif()

if(QUIC_TLS STREQUAL "mitls")
    # Build Everest.
    add_subdirectory(submodules/everest/msquic/msvc/kremlib)
    add_subdirectory(submodules/everest/msquic/msvc/evercrypt)
    add_subdirectory(submodules/everest/msquic/msvc/mitls)
    add_subdirectory(submodules/everest/msquic/msvc/quiccrypto)
endif()

# Product code
add_subdirectory(src/core)
add_subdirectory(src/platform)
add_subdirectory(src/bin)

# Tool code
if(QUIC_BUILD_TOOLS)
    add_subdirectory(src/tools/attack)
    add_subdirectory(src/tools/interop)
    add_subdirectory(src/tools/interopserver)
    add_subdirectory(src/tools/ping)
    add_subdirectory(src/tools/post)
    add_subdirectory(src/tools/reach)
    add_subdirectory(src/tools/sample)
    add_subdirectory(src/tools/siduck)
    add_subdirectory(src/tools/spin)
    add_subdirectory(src/tools/void)
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        add_subdirectory(src/tools/etwlib)
        add_subdirectory(src/tools/etw)
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
    enable_testing()
    add_subdirectory(submodules/googletest)

    add_subdirectory(src/core/unittest)
    add_subdirectory(src/platform/unittest)
    add_subdirectory(src/test/lib)
    add_subdirectory(src/test/bin)
endif()
