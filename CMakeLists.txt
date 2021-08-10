# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    cmake_minimum_required(VERSION 3.20)
else()
    cmake_minimum_required(VERSION 3.16)
endif()

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

message(STATUS "CMAKE Version: ${CMAKE_VERSION}")

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

message(STATUS "Source Dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Host System name: ${CMAKE_HOST_SYSTEM_NAME}")
if ("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    set(CMAKE_SYSTEM_VERSION 10.0.18362.0 CACHE STRING INTERNAL FORCE)
    set(CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION 10.0.18362.0 CACHE STRING INTERNAL FORCE)
endif()

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
    message(STATUS "Setting policy 0091")
else()
    message(WARNING "CMake version too old to support Policy 0091; CRT static linking won't work")
endif()

if (POLICY CMP0111)
    cmake_policy(SET CMP0111 NEW)
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
    set(CX_PLATFORM "windows")
elseif (APPLE)
    set(CX_PLATFORM "darwin")
elseif (UNIX)
    set(CX_PLATFORM "linux")
endif()
message(STATUS "QUIC Platform: ${CX_PLATFORM}")

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
option(QUIC_BUILD_SHARED "Builds msquic as a dynamic library" ON)
option(QUIC_ENABLE_LOGGING "Enables logging" OFF)
option(QUIC_ENABLE_SANITIZERS "Enables sanitizers" OFF)
option(QUIC_STATIC_LINK_CRT "Statically links the C runtime" ON)
option(QUIC_UWP_BUILD "Build for UWP" OFF)
option(QUIC_PGO "Enables profile guided optimizations" OFF)
option(QUIC_SOURCE_LINK "Enables source linking on MSVC" ON)
option(QUIC_PDBALTPATH "Enable PDBALTPATH setting on MSVC" ON)
option(QUIC_CODE_CHECK "Run static code checkers" OFF)
option(QUIC_OPTIMIZE_LOCAL "Optimize code for local machine architecture" OFF)
option(QUIC_CI "CI Specific build" OFF)
option(QUIC_SKIP_CI_CHECKS "Disable CI specific build checks" OFF)
option(QUIC_TLS_SECRETS_SUPPORT "Enable export of TLS secrets" OFF)
option(QUIC_TELEMETRY_ASSERTS "Enable telemetry asserts in release builds" OFF)
option(QUIC_USE_SYSTEM_LIBCRYPTO "Use system libcrypto if openssl TLS" OFF)
option(QUIC_DISABLE_POSIX_GSO "Disable GSO for systems that say they support it but don't" OFF)
set(QUIC_FOLDER_PREFIX "" CACHE STRING "Optional prefix for source group folders when using an IDE generator")
set(QUIC_LIBRARY_NAME "msquic" CACHE STRING "Override the output library name")

set(BUILD_SHARED_LIBS ${QUIC_BUILD_SHARED})

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
        file(TO_NATIVE_PATH "${PROJECT_SOURCE_DIR}/cmake/source_link.json.in" SOURCE_LINK_JSON_INPUT)
        source_link(${PROJECT_SOURCE_DIR} ${SOURCE_LINK_JSON} ${SOURCE_LINK_JSON_INPUT})
        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /INCREMENTAL:NO")
        set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /INCREMENTAL:NO")
        set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} /INCREMENTAL:NO")
        set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO} /INCREMENTAL:NO")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /FORCE:PGOREPRO /SOURCELINK:\"${SOURCE_LINK_JSON}\"")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /FORCE:PGOREPRO /SOURCELINK:\"${SOURCE_LINK_JSON}\"")
    else()
        message(WARNING "Disabling SourceLink due to old version of MSVC. Please update to VS2019!")
    endif()
endif()

set(QUIC_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(QUIC_OUTPUT_DIR ${QUIC_BUILD_DIR}/bin/$<IF:$<CONFIG:Debug>,Debug,Release> CACHE STRING "Output directory for build artifacts")

set(QUIC_VER_BUILD_ID "0" CACHE STRING "The version build ID")
set(QUIC_VER_SUFFIX "-private" CACHE STRING "The version suffix")

message(STATUS "Version Build ID: ${QUIC_VER_BUILD_ID}")
message(STATUS "Version Suffix: ${QUIC_VER_SUFFIX}")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${QUIC_BUILD_DIR}/obj/$<IF:$<CONFIG:Debug>,Debug,Release>)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${QUIC_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${QUIC_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${QUIC_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${QUIC_OUTPUT_DIR})

set(QUIC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/inc)

if (WIN32)
    set(QUIC_WARNING_FLAGS /WX /W4 /sdl CACHE INTERNAL "")
    set(QUIC_COMMON_FLAGS "")

    include(CheckCCompilerFlag)

    if(NOT QUIC_ENABLE_SANITIZERS)
        check_c_compiler_flag(/Qspectre HAS_SPECTRE)
    endif()
    if(HAS_SPECTRE)
        list(APPEND QUIC_COMMON_FLAGS /Qspectre)
    endif()

    check_c_compiler_flag(/guard:cf HAS_GUARDCF)
    if(HAS_GUARDCF)
        list(APPEND QUIC_COMMON_FLAGS /guard:cf)
    endif()

    # Require /Qspectre and /guard:cf in CI builds
    if(QUIC_CI AND NOT QUIC_SKIP_CI_CHECKS)
        if(NOT HAS_GUARDCF)
            message(FATAL_ERROR "/guard:cf must exist for CI builds")
        endif()
        if(NOT HAS_SPECTRE AND NOT QUIC_ENABLE_SANITIZERS AND NOT QUIC_UWP_BUILD)
            message(FATAL_ERROR "/Qspectre must exist for CI builds")
        endif()
    endif()

    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        list(APPEND QUIC_COMMON_FLAGS /MP)
    endif()
    set(QUIC_COMMON_DEFINES WIN32_LEAN_AND_MEAN SECURITY_WIN32)
else()

    if (CX_PLATFORM STREQUAL "linux")
        include(CheckCCompilerFlag)
        check_c_source_compiles(
            "
            #include <netinet/udp.h>
            int main() { return UDP_SEGMENT; }
            "
            HAS_UDP_SEGMENT)
        if (NOT HAS_UDP_SEGMENT)
            message(STATUS "UDP_SEGMENT is missing. Send performance will be reduced")
        endif()

        check_c_source_compiles(
            "
            #include <sys/socket.h>
            int main() { return SO_ATTACH_REUSEPORT_CBPF; }
            "
            HAS_SO_ATTACH_REUSEPORT_CBPF)
        if(NOT HAS_SO_ATTACH_REUSEPORT_CBPF)
            message(STATUS "SO_ATTACH_REUSEPORT_CBPF is missing. Server receive performance will be reduced")
        endif()

        # Error if flags are missing in CI
        if(QUIC_CI AND NOT QUIC_SKIP_CI_CHECKS)
            if (NOT HAS_UDP_SEGMENT)
                message(FATAL_ERROR "UDP_SEGMENT must exist for CI builds")
            endif()

            if(NOT HAS_SO_ATTACH_REUSEPORT_CBPF)
                message(FATAL_ERROR "SO_ATTACH_REUSEPORT_CBPF must exist for CI builds")
            endif()
        endif()

        # Check to see if lttng will work
        if(QUIC_ENABLE_LOGGING)
            check_c_source_compiles(
                "
                #include <lttng/ust-config.h>
                #ifdef LTTNG_UST_HAVE_SDT_INTEGRATION
                #error \"SDT is enabled\"
                #endif
                int main() { return 0; }
                "
                HAS_LTTNG_WITHOUT_SDT)
            if(NOT HAS_LTTNG_WITHOUT_SDT)
                message(WARNING "LTTng with SDT integration does not work. Disabling logging")
                set(QUIC_ENABLE_LOGGING OFF)
            endif()
        endif()
    endif()

    set(QUIC_COMMON_FLAGS "")
    set(QUIC_COMMON_DEFINES _GNU_SOURCE)
    set(QUIC_WARNING_FLAGS -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits
        -Wno-unknown-pragmas -Wno-multichar -Wno-missing-field-initializers
        CACHE INTERNAL "")
    if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 7.0)
        list(APPEND QUIC_WARNING_FLAGS -Wno-strict-aliasing)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        list(APPEND QUIC_WARNING_FLAGS -Wno-missing-braces -Wno-microsoft-anon-tag)
    endif()
endif()

list(APPEND QUIC_COMMON_DEFINES VER_BUILD_ID=${QUIC_VER_BUILD_ID})
list(APPEND QUIC_COMMON_DEFINES VER_SUFFIX=${QUIC_VER_SUFFIX})

if(QUIC_TLS_SECRETS_SUPPORT)
    list(APPEND QUIC_COMMON_DEFINES CXPLAT_TLS_SECRETS_SUPPORT=1)
endif()

if(QUIC_TELEMETRY_ASSERTS)
    list(APPEND QUIC_COMMON_DEFINES QUIC_TELEMETRY_ASSERTS=1)
endif()

if(QUIC_TLS STREQUAL "schannel")
    message(STATUS "Enabling Schannel configuration tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_TEST_SCHANNEL_FLAGS=1)
    message(STATUS "Enabling UDP Send Queuing")
    list(APPEND QUIC_COMMON_DEFINES CXPLAT_DATAPATH_QUEUE_SENDS=1)
    message(STATUS "Disabling PFX tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_PFX_TESTS)
    message(STATUS "Disabling portable certificate tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_PORTABLE_CERTIFICATE_TESTS)
    message(STATUS "Disabling 0-RTT support")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_0RTT_TESTS)
    message(STATUS "Disabling ChaCha20 support")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_CHACHA20_TESTS)
endif()

if(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Enabling OpenSsl configuration tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_TEST_OPENSSL_FLAGS=1)
    message(STATUS "Disabling client certificate tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_CLIENT_CERT_TESTS)
    message(STATUS "Disabling deferred certificate tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_DEFERRED_CERT_TESTS)
endif()

if (CMAKE_GENERATOR_PLATFORM STREQUAL "")
    string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} SYSTEM_PROCESSOR)
else()
    string(TOLOWER ${CMAKE_GENERATOR_PLATFORM} SYSTEM_PROCESSOR)
endif()

if(WIN32)
    # Generate the MsQuicEtw header file.
    file(MAKE_DIRECTORY ${QUIC_BUILD_DIR}/inc)

    add_custom_command(
        OUTPUT ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h
        OUTPUT ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/manifest/MsQuicEtw.man
        COMMAND mc.exe -um -h ${QUIC_BUILD_DIR}/inc -r ${QUIC_BUILD_DIR}/inc ${CMAKE_CURRENT_SOURCE_DIR}/src/manifest/MsQuicEtw.man)
    add_custom_target(MsQuicEtw_HeaderBuild
        DEPENDS ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h)

    set_property(TARGET MsQuicEtw_HeaderBuild PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}helpers")

    add_library(MsQuicEtw_Header INTERFACE)
    target_include_directories(MsQuicEtw_Header INTERFACE ${QUIC_BUILD_DIR}/inc)
    add_dependencies(MsQuicEtw_Header MsQuicEtw_HeaderBuild)

    add_library(MsQuicEtw_Resource OBJECT ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)
    set_property(TARGET MsQuicEtw_Resource PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}helpers")

    message(STATUS "Disabling (client) shared port support")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_SHARED_PORT_TESTS)

    if (QUIC_UWP_BUILD)
        list(APPEND QUIC_COMMON_DEFINES WINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP QUIC_UWP_BUILD)
    endif()

    if(QUIC_ENABLE_LOGGING)
        message(STATUS "Configuring for manifested ETW tracing")
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_MANIFEST_ETW QUIC_LOGS_MANIFEST_ETW)
    else()
        message(STATUS "Disabling tracing")
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STUB QUIC_LOGS_STUB)
    endif()

    if(QUIC_ENABLE_SANITIZERS)
        # This fails when linking statically, so for today require dynamic linkage
        if (QUIC_STATIC_LINK_CRT)
            message(FATAL_ERROR "Static linkage unsupported with Address Sanitizer in Windows")
        endif()
        message(STATUS "Configuring sanitizers")
        list(APPEND QUIC_COMMON_FLAGS /fsanitize=address)
    endif()

    set(QUIC_C_FLAGS ${QUIC_COMMON_FLAGS})
    set(QUIC_CXX_FLAGS ${QUIC_COMMON_FLAGS} /EHsc /permissive-)

    # These cannot be updated until CMake 3.13
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /DEBUG /OPT:REF /OPT:ICF")

    # Configure PGO linker flags.
    set(QUIC_PGO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/bin/winuser/pgo_${SYSTEM_PROCESSOR}/msquic.pgd")
    if(QUIC_PGO)
        # Configured for training mode. Use the previous PGD file if present.
        if(EXISTS "${QUIC_PGO_FILE}")
            message(STATUS "/GENPROFILE:PDG")
            configure_file("${QUIC_PGO_FILE}" "${QUIC_OUTPUT_DIR}/msquic.pgd" COPYONLY)
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /GENPROFILE:\"PGD=${QUIC_OUTPUT_DIR}/msquic.pgd\"")
        else()
            message(STATUS "/GENPROFILE")
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /GENPROFILE")
        endif()
    else()
        # Just doing a normal build. Use the PGD file if present.
        if(EXISTS "${QUIC_PGO_FILE}")
            message(STATUS "Using profile-guided optimization")
            configure_file("${QUIC_PGO_FILE}" "${QUIC_OUTPUT_DIR}/msquic.pgd" COPYONLY)
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /USEPROFILE:\"PGD=${QUIC_OUTPUT_DIR}/msquic.pgd\"")
        endif()
    endif()

    if(QUIC_STATIC_LINK_CRT)
        message(STATUS "Configuring for statically-linked CRT")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

else() #!WIN32
    # Custom build flags.

    if (QUIC_OPTIMIZE_LOCAL AND NOT CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
        set(MARCH -march=native)
    endif()
    set(CMAKE_C_FLAGS_DEBUG "-Og -ggdb3")
    set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 ${MARCH} -ggdb3 -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O3 ${MARCH} -DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    set(CMAKE_CXX_FLAGS_MINSIZEREL ${CMAKE_C_FLAGS_MINSIZEREL})
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_C_FLAGS_RELWITHDEBINFO})
    set(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})

    list(APPEND QUIC_COMMON_FLAGS -fms-extensions -fPIC)
    if (CX_PLATFORM STREQUAL "darwin")
        list(APPEND QUIC_COMMON_DEFINES CX_PLATFORM_DARWIN)
        list(APPEND QUIC_COMMON_FLAGS -Wno-microsoft-anon-tag -Wno-tautological-constant-out-of-range-compare -Wmissing-field-initializers)
        message(STATUS "Disabling (client) shared port support")
        list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_SHARED_PORT_TESTS)
    else()
        list(APPEND QUIC_COMMON_DEFINES CX_PLATFORM_LINUX)
        message(STATUS "Enabling shared ephemeral port work around")
        list(APPEND QUIC_COMMON_DEFINES QUIC_SHARED_EPHEMERAL_WORKAROUND)
    endif()

    if (QUIC_DISABLE_POSIX_GSO)
        list(APPEND QUIC_COMMON_DEFINES DISABLE_POSIX_GSO)
    endif()

    if (QUIC_ENABLE_SANITIZERS)
        set(QUIC_ENABLE_LOGGING OFF)
        message(WARNING "LTTng logging is incompatible with sanitizers. Skipping logging")
    endif()

    if(QUIC_ENABLE_LOGGING)
        if (APPLE)
            set (QUIC_ENABLE_LOGGING OFF)
            message(STATUS "Disabling all tracing on macos")
            list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STUB QUIC_LOGS_STUB)
        else()
            message(STATUS "Configuring for LTTng tracing")
            list(APPEND QUIC_COMMON_DEFINES QUIC_CLOG)
            set (QUIC_LTTNG_PLATFORM linux)
            include(FindLTTngUST)
        endif()
    else()
        message(STATUS "Disabling tracing")
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STUB QUIC_LOGS_STUB)
    endif()

    if(QUIC_ENABLE_SANITIZERS)
        message(STATUS "Configuring sanitizers")
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=address,leak,undefined -fsanitize-address-use-after-scope -Og -ggdb3 -fno-omit-frame-pointer -fno-optimize-sibling-calls)
        if (CMAKE_C_COMPILER_ID MATCHES "Clang")
            list(APPEND QUIC_COMMON_FLAGS -fsanitize=unsigned-integer-overflow -fsanitize=local-bounds -fsanitize=integer -fsanitize=nullability)
        endif()
    endif()

    set(QUIC_C_FLAGS ${QUIC_COMMON_FLAGS})
    set(QUIC_CXX_FLAGS ${QUIC_COMMON_FLAGS})
endif()

if(QUIC_TLS STREQUAL "openssl")
    if (WIN32)
        add_library(OpenSSL INTERFACE)

        include(FetchContent)

        FetchContent_Declare(
            OpenSSLQuic
            SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/submodules
            CMAKE_ARGS "-DQUIC_BUILD_DIR=${QUIC_BUILD_DIR}"
        )
        FetchContent_MakeAvailable(OpenSSLQuic)

        target_link_libraries(OpenSSL
            INTERFACE
            OpenSSLQuic::OpenSSLQuic
        )
    else()
        # Configure and build OpenSSL.
        set(OPENSSL_DIR ${QUIC_BUILD_DIR}/openssl)
        set(OPENSSL_CONFIG_FLAGS
            enable-tls1_3 no-makedepend no-dgram no-ssl3 no-psk no-srp

            #
            # The following line is needed for the 3.0 branch.
            #
            # no-uplink no-cmp no-acvp_tests no-fips no-padlockeng no-siv

            no-zlib no-egd no-idea no-rc5 no-rc4 no-afalgeng
            no-comp no-cms no-ct no-srp no-srtp no-ts no-gost no-dso no-ec2m
            no-tls1 no-tls1_1 no-tls1_2 no-dtls no-dtls1 no-dtls1_2 no-ssl
            no-ssl3-method no-tls1-method no-tls1_1-method no-tls1_2-method no-dtls1-method no-dtls1_2-method
            no-siphash no-whirlpool no-aria no-bf no-blake2 no-sm2 no-sm3 no-sm4 no-camellia no-cast no-md4 no-mdc2 no-ocb no-rc2 no-rmd160 no-scrypt
            no-weak-ssl-ciphers no-shared no-tests --prefix=${OPENSSL_DIR})

        if (QUIC_ENABLE_SANITIZERS)
            list(APPEND OPENSSL_CONFIG_FLAGS enable-asan enable-ubsan)
        endif()
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
            set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl/Configure
                linux-armv4 -DL_ENDIAN
                --cross-compile-prefix=${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-)
            list(APPEND OPENSSL_CONFIG_FLAGS -latomic)
        elseif(CX_PLATFORM STREQUAL "darwin")
            # need to build with Apple's compiler
            if (CMAKE_OSX_ARCHITECTURES STREQUAL arm64)
                set(OPENSSL_CONFIG_CMD ARCHFLAGS="-arch arm64" ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl/Configure darwin64-arm64-cc)
            elseif(CMAKE_OSX_ARCHITECTURES STREQUAL x86_64)
                set(OPENSSL_CONFIG_CMD ARCHFLAGS="-arch x86_64" ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl/Configure darwin64-x86_64-cc)
            else()
                set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl/config)
            endif()
            list(APPEND OPENSSL_CONFIG_FLAGS -isysroot ${CMAKE_OSX_SYSROOT})
        elseif(ANDROID)
            message(STATUS "${ANDROID_ABI}")
            if(ANDROID_ABI STREQUAL "arm64-v8a")
                set(OPENSSL_BUILD_TYPE android-arm64)
            elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
                set(OPENSSL_BUILD_TYPE android-arm)
            elseif(ANDROID_ABI STREQUAL "x86")
                set(OPENSSL_BUILD_TYPE android-x86)
            elseif(ANDROID_ABI STREQUAL "x86_64")
                set(OPENSSL_BUILD_TYPE android-x86_64)
            else()
                message(FATAL_ERROR "Unknown android abi type")
            endif()
            set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl/Configure
                ${OPENSSL_BUILD_TYPE}
                -D__ANDROID_API__=29)
        else()
            set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/submodules/openssl/config
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

        file(MAKE_DIRECTORY ${OPENSSL_DIR}/include)

        add_library(OpenSSL STATIC IMPORTED)
        set_target_properties(OpenSSL PROPERTIES
            IMPORTED_LOCATION ${OPENSSL_DIR}/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
            IMPORTED_LINK_INTERFACE_LANGUAGES "C")

        target_include_directories(OpenSSL INTERFACE ${OPENSSL_DIR}/include)

        if (QUIC_USE_SYSTEM_LIBCRYPTO)
            include(FindOpenSSL)
            if (OPENSSL_FOUND)
                if (OPENSSL_VERSION VERSION_EQUAL 1.1.1)
                    target_link_libraries(OpenSSL INTERFACE OpenSSL::Crypto)
                else()
                    message(FATAL_ERROR "OpenSSL 1.1.1 not found, found ${OPENSSL_VERSION}")
                endif()
            else()
                message(FATAL_ERROR "System OpenSSL not found when requested")
            endif()
        else()
            add_library(OpenSSL_Crypto STATIC IMPORTED)
            set_target_properties(OpenSSL_Crypto PROPERTIES
                IMPORTED_LOCATION ${OPENSSL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX}
                IMPORTED_LINK_INTERFACE_LANGUAGES "C")

            add_dependencies(OpenSSL_Crypto OpenSSL_Build)
            target_link_libraries(OpenSSL INTERFACE OpenSSL_Crypto)
        endif()
        add_dependencies(OpenSSL OpenSSL_Build)
    endif()
endif()

if(QUIC_CODE_CHECK)
    find_program(CLANGTIDY NAMES clang-tidy)
    if(CLANGTIDY)
        message(STATUS "Found clang-tidy: ${CLANGTIDY}")
        set(CLANG_TIDY_CHECKS *
            # add checks to ignore here:
            -altera-struct-pack-align
            -android-cloexec-fopen
            -android-cloexec-socket
            -bugprone-macro-parentheses
            -bugprone-narrowing-conversions
            -bugprone-reserved-identifier
            -bugprone-sizeof-expression
            -cert-dcl37-c
            -cert-dcl51-cpp
            -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling
            -clang-diagnostic-microsoft-anon-tag
            -concurrency-mt-unsafe
            -cppcoreguidelines-avoid-magic-numbers
            -cppcoreguidelines-avoid-non-const-global-variables
            -cppcoreguidelines-init-variables
            -cppcoreguidelines-narrowing-conversions
            -google-readability-todo
            -hicpp-no-assembler
            -hicpp-signed-bitwise
            -llvmlibc-restrict-system-libc-headers
            -misc-no-recursion # do you really need recursion?
            -readability-avoid-const-params-in-decls
            -readability-function-cognitive-complexity
            -readability-isolate-declaration
            -readability-magic-numbers
            -readability-non-const-parameter
        )
        string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS}")
        set(CMAKE_C_CLANG_TIDY_AVAILABLE ${CLANGTIDY} -checks=${CLANG_TIDY_CHECKS}
            -system-headers --warnings-as-errors=*)
    else()
        message(STATUS "clang-tidy not found")
    endif()

    find_program(CPPCHECK NAMES cppcheck)
    if(CPPCHECK)
        message(STATUS "Found cppcheck: ${CPPCHECK}")
        set(CMAKE_C_CPPCHECK_AVAILABLE ${CPPCHECK} -q --inline-suppr
            --suppress=duplicateValueTernary --suppress=objectIndex
            --suppress=varFuncNullUB
            # these are finding potential logic issues, may want to suppress when focusing on nits:
            --suppress=nullPointer --suppress=nullPointerRedundantCheck
            --suppress=knownConditionTrueFalse
            --enable=warning,style,performance,portability -D__linux__)
    else()
        message(STATUS "cppcheck not found")
    endif()
endif()

add_subdirectory(src/inc)
add_subdirectory(src/generated)

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
    include(FetchContent)

    enable_testing()

    # Build the googletest framework.

    # Enforce static builds for test artifacts
    set(PREV_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS} CACHE INTERNAL "")
    set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject")
    set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest. (Projects embedding googletest may want to turn this OFF.)")
    if(WIN32 AND QUIC_STATIC_LINK_CRT)
        option(gtest_force_shared_crt "Use shared (DLL) run-time lib even when Google Test is built as static lib." ON)
    endif()
    FetchContent_Declare(
        googletest
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/submodules/googletest
    )
    FetchContent_MakeAvailable(googletest)
    set(BUILD_SHARED_LIBS ${PREV_BUILD_SHARED_LIBS} CACHE INTERNAL "")

    set_property(TARGET gtest PROPERTY CXX_STANDARD 17)
    set_property(TARGET gtest PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")

    set_property(TARGET gtest_main PROPERTY CXX_STANDARD 17)
    set_property(TARGET gtest_main PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tests")
    set_property(TARGET gtest_main PROPERTY EXCLUDE_FROM_ALL ON)
    set_property(TARGET gtest_main PROPERTY EXCLUDE_FROM_DEFAULT_BUILD ON)

    if (HAS_SPECTRE)
        target_compile_options(gtest PRIVATE /Qspectre)
        target_compile_options(gtest_main PRIVATE /Qspectre)
    endif()

    if (HAS_GUARDCF)
        target_compile_options(gtest PRIVATE /guard:cf)
        target_compile_options(gtest_main PRIVATE /guard:cf)
    endif()

    add_subdirectory(src/core/unittest)
    add_subdirectory(src/platform/unittest)
    add_subdirectory(src/test/lib)
    add_subdirectory(src/test/bin)
endif()
