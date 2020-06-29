# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

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

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # On Windows, we just need to set the destination variables
    # This will allow the build to be picked up by other projects
    set(msquic_dest ${CMAKE_INSTALL_PREFIX})
    set(main_lib_dest lib)
    set(include_dest include)
else()
    # On unix platforms, we need to do rpath manipulation for the shared library
    # In addition, we install into a subfolder of install to not polute the global namespace

    # Setup for Install. We set this up in here rather then in the main library folder for future use.
    # i.e. don't skip the full RPATH for the build tree
    set(CMAKE_SKIP_BUILD_RPATH FALSE)

    # When building, don't use the install RPATH already
    # (but later on when installing)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/msquic/lib")

    # Add the automatically determined parts of the RPATH
    # which point to directories outside the build tree to the install RPATH
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

    # The RPATH to be used when installing, but only if it's not a system directory
    list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/msquic/lib" isSystemDir)
    if("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/msquic/lib")
    endif("${isSystemDir}" STREQUAL "-1")

    set(msquic_dest msquic)
    set(main_lib_dest msquic/lib)
    set(include_dest msquic/include)
endif()

set(FILENAME_DEP_REPLACE "get_filename_component(SELF_DIR \"$\{CMAKE_CURRENT_LIST_FILE\}\" PATH)")
set(SELF_DIR "$\{SELF_DIR\}")

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
option(QUIC_UWP_BUILD "Build for UWP" OFF)
option(QUIC_PGO "Enables profile guided optimizations" OFF)

# FindLTTngUST does not exist before CMake 3.6, so disable logging for older cmake versions
if (${CMAKE_VERSION} VERSION_LESS "3.6.0")
    message(WARNING "Logging unsupported on this version of CMake. Please upgrade to 3.6 or later.")
    set(QUIC_ENABLE_LOGGING OFF)
endif()

if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    set(QUIC_PLATFORM "windows")
elseif ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Linux")
    set(QUIC_PLATFORM "linux")
elseif ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Darwin")
    set(QUIC_PLATFORM "darwin")
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
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/manifest/MsQuicEtw.man
        COMMAND mc.exe -um -h ${QUIC_BUILD_DIR}/inc -r ${QUIC_BUILD_DIR}/inc ${CMAKE_CURRENT_SOURCE_DIR}/src/manifest/MsQuicEtw.man)
    add_custom_target(MsQuicEtw
        DEPENDS ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h
        DEPENDS ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)

    set_property(TARGET MsQuicEtw PROPERTY FOLDER "libraries")

    # Custom build flags.
    set(QUIC_COMMON_FLAGS "-DWIN32_LEAN_AND_MEAN -DSECURITY_WIN32 /MP")

    if(QUIC_UWP_BUILD)
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DWINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP -DQUIC_UWP_BUILD")
    endif()

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
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /DEBUG /OPT:REF /OPT:ICF")

    # Configure PGO linker flags.
    set(QUIC_PGO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/bin/winuser/pgo_${CMAKE_GENERATOR_PLATFORM}/msquic.pgd")
    if(QUIC_PGO)
        # Configured for training mode. Use the previous PGD file if present.
        if(EXISTS "${QUIC_PGO_FILE}")
            message(STATUS "/GENPROFILE:PDG")
            configure_file("${QUIC_PGO_FILE}" "${QUIC_OUTPUT_DIR}/msquic.pgd" COPYONLY)
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /GENPROFILE:PGD=${QUIC_OUTPUT_DIR}/msquic.pgd")
        else()
            message(STATUS "/GENPROFILE")
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /GENPROFILE")
        endif()
    else()
        # Just doing a normal build. Use the PGD file if present.
        if(EXISTS "${QUIC_PGO_FILE}")
            message(STATUS "Using profile-guided optimization")
            configure_file("${QUIC_PGO_FILE}" "${QUIC_OUTPUT_DIR}/msquic.pgd" COPYONLY)
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /USEPROFILE:PGD=${QUIC_OUTPUT_DIR}/msquic.pgd")
        endif()
    endif()

    if(QUIC_STATIC_LINK_CRT)
        message(STATUS "Configuring for statically-linked CRT")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

else()
    # Custom build flags.

    set(QUIC_COMMON_FLAGS "-fms-extensions -fPIC -pthread")
    if (QUIC_PLATFORM STREQUAL "darwin")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_PLATFORM_DARWIN -Wno-microsoft-anon-tag -Wno-tautological-constant-out-of-range-compare -Wmissing-field-initializers")
    else()
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_PLATFORM_LINUX -Wl,--no-as-needed -ldl")
    endif()

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
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -fsanitize=address -fno-omit-frame-pointer -O0 -g")
    endif()

    if(QUIC_TLS STREQUAL "stub")
        set(QUIC_COMMON_FLAGS "${QUIC_COMMON_FLAGS} -DQUIC_TLS_STUB")
    endif()

    set(QUIC_C_FLAGS "${QUIC_COMMON_FLAGS}")
    set(QUIC_CXX_FLAGS "${QUIC_COMMON_FLAGS} -std=c++17 -g -Wno-reorder -Wno-sign-compare -Wno-format")
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/inc)

if(QUIC_TLS STREQUAL "openssl")
    # Configure and build OpenSSL.
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
        add_custom_command(
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl
            OUTPUT ${QUIC_BUILD_DIR}/openssl/include
            OUTPUT ${QUIC_BUILD_DIR}/openssl/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
            OUTPUT ${QUIC_BUILD_DIR}/openssl/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
            COMMAND SYSTEM=${CMAKE_HOST_SYSTEM_NAME} ./Configure linux-armv4 --cross-compile-prefix=${GNU_MACHINE}${FLOAT_ABI_SUFFIX}- -DL_ENDIAN enable-tls1_3 --prefix=${QUIC_BUILD_DIR}/openssl
            COMMAND make clean
            COMMAND make -j$$(nproc)
            COMMAND make install_sw)
    else ()
        add_custom_command(
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl
            OUTPUT ${QUIC_BUILD_DIR}/openssl/include
            OUTPUT ${QUIC_BUILD_DIR}/openssl/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
            OUTPUT ${QUIC_BUILD_DIR}/openssl/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
            COMMAND SYSTEM=${CMAKE_HOST_SYSTEM_NAME} ./config enable-tls1_3 --prefix=${QUIC_BUILD_DIR}/openssl
            COMMAND make -j$$(nproc)
            COMMAND make install_sw)
    endif()
    add_custom_target(OpenSSL
        DEPENDS ${QUIC_BUILD_DIR}/openssl/include
        DEPENDS ${QUIC_BUILD_DIR}/openssl/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
        DEPENDS ${QUIC_BUILD_DIR}/openssl/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})
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
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
    endif()

    enable_testing()
    add_subdirectory(submodules/googletest)

    set_property(TARGET gtest PROPERTY FOLDER "tests")
    set_property(TARGET gtest_main PROPERTY FOLDER "tests")

    add_subdirectory(src/core/unittest)
    add_subdirectory(src/platform/unittest)
    add_subdirectory(src/test/lib)
    add_subdirectory(src/test/bin)
endif()
