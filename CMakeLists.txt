# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

message(STATUS "CMAKE Version: ${CMAKE_VERSION}")

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

# Set a default build type if none was specified
set(default_build_type "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
        STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "System name: ${CMAKE_SYSTEM_NAME}")
message(STATUS "System version: ${CMAKE_SYSTEM_VERSION}")
message(STATUS "Platform version: ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

if (WIN32)
    set(QUIC_PLATFORM "windows")
elseif (APPLE)
    set(QUIC_PLATFORM "darwin")
elseif (UNIX)
    set(QUIC_PLATFORM "linux")
endif()
message(STATUS "QUIC Platform: ${QUIC_PLATFORM}")

if(WIN32)
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
    #set(CMAKE_SKIP_BUILD_RPATH FALSE)

    # When building, don't use the install RPATH already
    # (but later on when installing)
    #set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

    # Azure is not liking this argument. I think its a bug in their configuration
    # Once this is fixed, also fix the shim in build-config-user.yml
    #set(CMAKE_BUILD_RPATH_USE_ORIGIN TRUE)

    #set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/msquic/lib")

    # Add the automatically determined parts of the RPATH
    # which point to directories outside the build tree to the install RPATH
    #set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

    # The RPATH to be used when installing, but only if it's not a system directory
    list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/msquic/lib" isSystemDir)
    if("${isSystemDir}" STREQUAL "-1")
    #set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/msquic/lib")
    endif("${isSystemDir}" STREQUAL "-1")

    set(msquic_dest msquic)
    set(main_lib_dest msquic/lib)
    set(include_dest msquic/include)
endif()

set(FILENAME_DEP_REPLACE "get_filename_component(SELF_DIR \"$\{CMAKE_CURRENT_LIST_FILE\}\" PATH)")
set(SELF_DIR "$\{SELF_DIR\}")

enable_testing()

# Set the default TLS method for each platform.
if (WIN32)
    set(QUIC_TLS "schannel" CACHE STRING "TLS Library to use")
else()
    set(QUIC_TLS "openssl" CACHE STRING "TLS Library to use")
endif()

option(QUIC_BUILD_TOOLS "Builds the tools code" ON)
option(QUIC_BUILD_TEST "Builds the test code" ON)
option(QUIC_BUILD_PERF "Builds the perf code" ON)
option(QUIC_ENABLE_LOGGING "Enables logging" OFF)
option(QUIC_ENABLE_SANITIZERS "Enables sanitizers" OFF)
option(QUIC_STATIC_LINK_CRT "Statically links the C runtime" ON)
option(QUIC_UWP_BUILD "Build for UWP" OFF)
option(QUIC_PGO "Enables profile guided optimizations" OFF)
option(QUIC_SOURCE_LINK "Enables source linking on MSVC" ON)
option(QUIC_PDBALTPATH "Enable PDBALTPATH setting on MSVC" ON)
option(QUIC_CODE_CHECK "Run static code checkers" OFF)
option(QUIC_OPTIMIZE_LOCAL "Optimize code for local machine architecture" OFF)
option(QUIC_CI "CI Specific build optimizations" OFF)

# FindLTTngUST does not exist before CMake 3.6, so disable logging for older cmake versions
if (${CMAKE_VERSION} VERSION_LESS "3.6.0")
    message(WARNING "Logging unsupported on this version of CMake. Please upgrade to 3.6 or later.")
    set(QUIC_ENABLE_LOGGING OFF)
endif()

if (QUIC_PDBALTPATH AND MSVC)
#    Disabled in all cases because generation is broken.
#    file(READ ${CMAKE_CURRENT_LIST_DIR}/cmake/PdbAltPath.txt PDBALTPATH)
#    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${PDBALTPATH}")
#    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${PDBALTPATH}")
#    message(STATUS ${CMAKE_EXE_LINKER_FLAGS})
endif()

if (QUIC_SOURCE_LINK AND MSVC)
    if ("${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER_EQUAL "19.20")
        include(${PROJECT_SOURCE_DIR}/cmake/SourceLink.cmake)
        file(TO_NATIVE_PATH "${PROJECT_BINARY_DIR}/source_link.json" SOURCE_LINK_JSON)
        source_link(${PROJECT_SOURCE_DIR} ${SOURCE_LINK_JSON})
        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /INCREMENTAL:NO")
        set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /INCREMENTAL:NO")
        set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} /INCREMENTAL:NO")
        set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO} /INCREMENTAL:NO")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /FORCE:PGOREPRO /SOURCELINK:${SOURCE_LINK_JSON}")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /FORCE:PGOREPRO /SOURCELINK:${SOURCE_LINK_JSON}")
    else()
        message(WARNING "Disabling SourceLink due to old version of MSVC. Please update to VS2019!")
    endif()
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

if (QUIC_ENABLE_LOGGING)
    execute_process(COMMAND clog --installDirectory ${QUIC_BUILD_DIR}/clog)

    set(CMAKE_CLOG_OUTPUT_DIRECTORY ${QUIC_BUILD_DIR}/inc)
    set(CMAKE_CLOG_SIDECAR_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/manifest)
    set(CLOG_INCLUDE_DIRECTORY ${QUIC_BUILD_DIR}/clog)
    set(CMAKE_CLOG_GENERATE_FILE ${QUIC_BUILD_DIR}/clog/CLog.cmake)
    set(CMAKE_CLOG_CONFIG_FILE ${CMAKE_CURRENT_SOURCE_DIR}/src/manifest/msquic.clog_config)
    include(${CMAKE_CLOG_GENERATE_FILE})

    function(add_clog_library)
        CLOG_GENERATE_TARGET(${ARGV})
        target_link_libraries(${ARGV0} PRIVATE inc)
        set_property(TARGET ${ARGV0} PROPERTY FOLDER "clog")
    endfunction()
else()
    function(add_clog_library)
        add_library(${ARGV0} INTERFACE)
    endfunction()
endif()

set(QUIC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/inc)
set(MANIFESTED_HEADER_FILENAME ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h)

if (WIN32)
    set(QUIC_WARNING_FLAGS /WX /W4 /sdl CACHE INTERNAL "")
    set(QUIC_COMMON_FLAGS "")
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        list(APPEND QUIC_COMMON_FLAGS /MP)
    endif()
    set(QUIC_COMMON_DEFINES WIN32_LEAN_AND_MEAN SECURITY_WIN32)
else()
    set(QUIC_COMMON_FLAGS "")
    set(QUIC_COMMON_DEFINES "")
    set(QUIC_WARNING_FLAGS -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits
        -Wno-unknown-pragmas -Wno-multichar -Wno-missing-field-initializers
        CACHE INTERNAL "")
    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        list(APPEND QUIC_WARNING_FLAGS -Wno-missing-braces -Wno-microsoft-anon-tag)
    endif()
endif()

if(WIN32)
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

    if (QUIC_UWP_BUILD)
        list(APPEND QUIC_COMMON_DEFINES WINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP QUIC_UWP_BUILD)
    endif()

    if(QUIC_ENABLE_LOGGING)
        message(STATUS "Configuring for manifested ETW tracing")
        set(CMAKE_CLOG_CONFIG_PROFILE windows)
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_MANIFEST_ETW QUIC_LOGS_MANIFEST_ETW)
    else()
        message(STATUS "Disabling tracing")
        set(CMAKE_CLOG_CONFIG_PROFILE stubs)
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STUB QUIC_LOGS_STUB)
    endif()

    if(QUIC_TLS STREQUAL "openssl")
        # OpenSSL doesn't support session resumption yet.
        message(STATUS "Disabling session resumption support")
        list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_RESUMPTION)
    endif()

    if(QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "schannel")
        # OpenSSL and SChannel don't support 0-RTT yet.
        message(STATUS "Disabling 0-RTT support")
        list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_0RTT_TESTS)
    endif()

    if(QUIC_TLS STREQUAL "stub")
        list(APPEND QUIC_COMMON_DEFINES QUIC_TLS_STUB)
    endif()

    if(QUIC_ENABLE_SANITIZERS)
        message(STATUS "Sanitizers unsupported on this platform.")
    endif()

    set(QUIC_C_FLAGS ${QUIC_COMMON_FLAGS})
    set(QUIC_CXX_FLAGS ${QUIC_COMMON_FLAGS} /EHsc)

    # These cannot be updated until CMake 3.13
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

    if (QUIC_OPTIMIZE_LOCAL AND NOT CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
        set(MARCH -march=native)
    endif()
    set(CMAKE_C_FLAGS_DEBUG "-Og -ggdb3")
    set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-Ofast ${MARCH} -ggdb3 -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-Ofast ${MARCH} -DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    set(CMAKE_CXX_FLAGS_MINSIZEREL ${CMAKE_C_FLAGS_MINSIZEREL})
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_C_FLAGS_RELWITHDEBINFO})
    set(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})

    list(APPEND QUIC_COMMON_FLAGS -fms-extensions -fPIC)
    if (QUIC_PLATFORM STREQUAL "darwin")
        list(APPEND QUIC_COMMON_DEFINES QUIC_PLATFORM_DARWIN)
        list(APPEND QUIC_COMMON_FLAGS -Wno-microsoft-anon-tag -Wno-tautological-constant-out-of-range-compare -Wmissing-field-initializers)
    else()
        list(APPEND QUIC_COMMON_DEFINES QUIC_PLATFORM_LINUX)
    endif()

    if (QUIC_ENABLE_SANITIZERS)
        set(QUIC_ENABLE_LOGGING OFF)
        message(WARNING "LTTng logging is incompatible with sanitizers. Skipping logging")
    endif()

    if(QUIC_ENABLE_LOGGING)
        message(STATUS "Configuring for LTTng tracing")
        set(CMAKE_CLOG_CONFIG_PROFILE linux)
        list(APPEND QUIC_COMMON_DEFINES QUIC_CLOG)
        include(FindLTTngUST)
    else()
        message(STATUS "Disabling tracing")
        set(CMAKE_CLOG_CONFIG_PROFILE stubs)
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STUB QUIC_LOGS_STUB)
        list(APPEND QUIC_WARNING_FLAGS -Wno-unused-parameter -Wno-unused-variable)
    endif()

    if(QUIC_TLS STREQUAL "openssl")
        # OpenSSL doesn't support session resumption yet.
        message(STATUS "Disabling session resumption support")
        list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_RESUMPTION)
        # OpenSSL doesn't support 0-RTT yet.
        message(STATUS "Disabling 0-RTT support")
        list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_0RTT_TESTS)
    endif()

    if(QUIC_ENABLE_SANITIZERS)
        message(STATUS "Configuring sanitizers")
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=address,leak,undefined -fsanitize-address-use-after-scope -Og -ggdb3 -fno-omit-frame-pointer -fno-optimize-sibling-calls)
        if (CMAKE_C_COMPILER_ID MATCHES "Clang")
            list(APPEND QUIC_COMMON_FLAGS -fsanitize=unsigned-integer-overflow -fsanitize=local-bounds -fsanitize=integer -fsanitize=nullability)
        endif()
    endif()

    if(QUIC_TLS STREQUAL "stub")
        list(APPEND QUIC_COMMON_DEFINES QUIC_TLS_STUB)
    endif()

    set(QUIC_C_FLAGS ${QUIC_COMMON_FLAGS})
    set(QUIC_CXX_FLAGS ${QUIC_COMMON_FLAGS})
endif()

if(QUIC_TLS STREQUAL "openssl")
    if (WIN32)
        set(OPENSSL_DIR ${QUIC_BUILD_DIR}/openssl)

        add_library(OpenSSL_Crypto STATIC IMPORTED)
        set_property(TARGET OpenSSL_Crypto PROPERTY IMPORTED_LOCATION_RELEASE ${OPENSSL_DIR}/release/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})
        set_property(TARGET OpenSSL_Crypto PROPERTY IMPORTED_LOCATION_DEBUG   ${OPENSSL_DIR}/debug/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})


        add_library(OpenSSL STATIC IMPORTED)
        set_property(TARGET OpenSSL PROPERTY IMPORTED_LOCATION_RELEASE ${OPENSSL_DIR}/release/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})
        set_property(TARGET OpenSSL PROPERTY IMPORTED_LOCATION_DEBUG   ${OPENSSL_DIR}/debug/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})

        target_include_directories(OpenSSL INTERFACE
                $<$<CONFIG:Debug>:${OPENSSL_DIR}/debug/include>
                $<$<CONFIG:Release>:${OPENSSL_DIR}/release/include>)
        target_link_libraries(OpenSSL INTERFACE OpenSSL_Crypto)

        if (QUIC_CI AND EXISTS ${OPENSSL_DIR}/release/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})
            message(STATUS "Found existing OpenSSL cache, skipping openssl build")
        else()
            file(MAKE_DIRECTORY ${OPENSSL_DIR}/debug/include)
            file(MAKE_DIRECTORY ${OPENSSL_DIR}/release/include)

            set(OPENSSL_CONFIG_FLAGS
                enable-tls1_3 no-makedepend no-dgram no-ssl3 no-psk no-srp
                no-weak-ssl-ciphers no-shared no-tests VC-WIN64A)

            add_custom_target(mkdir_openssl_build_debug
                COMMAND if not exist \"${QUIC_BUILD_DIR}/submodules/openssl/debug\" mkdir \"${QUIC_BUILD_DIR}/submodules/openssl/debug\" 2> NUL)
            add_custom_target(mkdir_openssl_build_release
                COMMAND if not exist \"${QUIC_BUILD_DIR}/submodules/openssl/release\" mkdir \"${QUIC_BUILD_DIR}/submodules/openssl/release\" 2> NUL)
            add_custom_command(
                DEPENDS mkdir_openssl_build_debug
                WORKING_DIRECTORY ${QUIC_BUILD_DIR}/submodules/openssl/debug
                OUTPUT ${OPENSSL_DIR}/debug/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
                OUTPUT ${OPENSSL_DIR}/debug/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
                COMMAND perl ${CMAKE_SOURCE_DIR}/submodules/openssl/Configure ${OPENSSL_CONFIG_FLAGS} --debug --prefix=${OPENSSL_DIR}/debug
                COMMAND nmake
                COMMAND nmake install_dev)

            add_custom_command(
                DEPENDS mkdir_openssl_build_release
                WORKING_DIRECTORY ${QUIC_BUILD_DIR}/submodules/openssl/release
                OUTPUT ${OPENSSL_DIR}/release/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
                OUTPUT ${OPENSSL_DIR}/release/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
                COMMAND perl ${CMAKE_SOURCE_DIR}/submodules/openssl/Configure ${OPENSSL_CONFIG_FLAGS} --prefix=${OPENSSL_DIR}/release
                COMMAND nmake
                COMMAND nmake install_dev)

            add_custom_target(OpenSSL_Build_Debug
                DEPENDS ${OPENSSL_DIR}/debug/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
                DEPENDS ${OPENSSL_DIR}/debug/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})

            add_custom_target(OpenSSL_Build_Release
                DEPENDS ${OPENSSL_DIR}/release/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
                DEPENDS ${OPENSSL_DIR}/release/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})

            add_dependencies(OpenSSL_Crypto OpenSSL_Build_Release OpenSSL_Build_Debug)
            add_dependencies(OpenSSL OpenSSL_Build_Release OpenSSL_Build_Debug)
        endif()
    else()
        # Configure and build OpenSSL.
        set(OPENSSL_DIR ${QUIC_BUILD_DIR}/openssl)
        set(OPENSSL_CONFIG_FLAGS
            enable-tls1_3 no-makedepend no-dgram no-ssl3 no-psk no-srp
            no-weak-ssl-ciphers no-shared no-tests --prefix=${OPENSSL_DIR})
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
            set(OPENSSL_CONFIG_CMD ${CMAKE_SOURCE_DIR}/submodules/openssl/Configure
                linux-armv4 -DL_ENDIAN
                --cross-compile-prefix=${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-)
        else()
            set(OPENSSL_CONFIG_CMD ${CMAKE_SOURCE_DIR}/submodules/openssl/config
                CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER})
        endif()
        add_custom_target(mkdir_openssl_build
            COMMAND mkdir -p ${QUIC_BUILD_DIR}/submodules/openssl)
        add_custom_command(
            DEPENDS mkdir_openssl_build
            WORKING_DIRECTORY ${QUIC_BUILD_DIR}/submodules/openssl
            OUTPUT ${OPENSSL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
            OUTPUT ${OPENSSL_DIR}/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
            COMMAND SYSTEM=${CMAKE_HOST_SYSTEM_NAME}
                ${OPENSSL_CONFIG_CMD} ${OPENSSL_CONFIG_FLAGS}
            COMMAND make -j$$(nproc)
            COMMAND make install_dev)
        add_custom_target(OpenSSL_Build
            DEPENDS ${OPENSSL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
            DEPENDS ${OPENSSL_DIR}/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})

        add_library(OpenSSL_Crypto STATIC IMPORTED)
        set_property(TARGET OpenSSL_Crypto PROPERTY IMPORTED_LOCATION   ${OPENSSL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})
        add_dependencies(OpenSSL_Crypto OpenSSL_Build)

        file(MAKE_DIRECTORY ${OPENSSL_DIR}/include)

        add_library(OpenSSL STATIC IMPORTED)
        set_property(TARGET OpenSSL PROPERTY IMPORTED_LOCATION ${OPENSSL_DIR}/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})
        target_include_directories(OpenSSL INTERFACE ${OPENSSL_DIR}/include)
        target_link_libraries(OpenSSL INTERFACE OpenSSL_Crypto)
        add_dependencies(OpenSSL OpenSSL_Build)
    endif()
endif()

if(QUIC_TLS STREQUAL "mitls")
    # Build Everest.
    add_subdirectory(submodules/everest/msquic/msvc/kremlib)
    add_subdirectory(submodules/everest/msquic/msvc/evercrypt)
    add_subdirectory(submodules/everest/msquic/msvc/mitls)
    add_subdirectory(submodules/everest/msquic/msvc/quiccrypto)
endif()

if(QUIC_CODE_CHECK)
    find_program(CLANGTIDY NAMES clang-tidy)
    if(CLANGTIDY)
        message(STATUS "Found clang-tidy: ${CLANGTIDY}")
        set(CLANG_TIDY_CHECKS *
            # add checks to ignore here, e.g.,
            # -hicpp-no-assembler
            # -hicpp-signed-bitwise
            # ...
        )
        string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS}")
        set(CMAKE_C_CLANG_TIDY ${CLANGTIDY} -checks=${CLANG_TIDY_CHECKS}
            -system-headers)
        set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY})
    else()
        message(STATUS "clang-tidy not found")
    endif()

    find_program(CPPCHECK NAMES cppcheck)
    if(CPPCHECK)
        message(STATUS "Found cppcheck: ${CPPCHECK}")
        set(CMAKE_C_CPPCHECK ${CPPCHECK} -q --inline-suppr
            --enable=warning,style,performance,portability -D__linux__)
        set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK})
    else()
        message(STATUS "cppcheck not found")
    endif()
endif()

add_subdirectory(src/inc)

# Product code
add_subdirectory(src/core)
add_subdirectory(src/platform)
add_subdirectory(src/bin)

# Tool code
if(QUIC_BUILD_TOOLS)
    add_subdirectory(src/tools)
endif()

# Performance code
if(QUIC_BUILD_PERF)
    add_subdirectory(src/perf/lib)
    add_subdirectory(src/perf/bin)
endif()

# Test code
if(QUIC_BUILD_TEST)
    # Build the googletest framework.
    set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject")
    set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest. (Projects embedding googletest may want to turn this OFF.)")
    if(WIN32)
        option(gtest_force_shared_crt "Use shared (DLL) run-time lib even when Google Test is built as static lib." ON)
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
