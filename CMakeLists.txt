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

set(QUIC_MAJOR_VERSION 2)
set(QUIC_FULL_VERSION 2.1.0)

if (WIN32)
    set(CX_PLATFORM "windows")
elseif (APPLE)
    set(CX_PLATFORM "darwin")
elseif (UNIX)
    set(CX_PLATFORM "linux")
endif()
message(STATUS "QUIC Platform: ${CX_PLATFORM}")

set(FILENAME_DEP_REPLACE "get_filename_component(SELF_DIR \"$\{CMAKE_CURRENT_LIST_FILE\}\" PATH)")
set(SELF_DIR "$\{SELF_DIR\}")

enable_testing()

# Set the default TLS method for each platform.
if (WIN32)
    set(QUIC_TLS "schannel" CACHE STRING "TLS Library to use")
else()
    set(QUIC_TLS "openssl" CACHE STRING "TLS Library to use")
endif()

option(QUIC_BUILD_TOOLS "Builds the tools code" OFF)
option(QUIC_BUILD_TEST "Builds the test code" OFF)
option(QUIC_BUILD_PERF "Builds the perf code" OFF)
option(QUIC_BUILD_SHARED "Builds msquic as a dynamic library" ON)
option(QUIC_ENABLE_LOGGING "Enables logging" OFF)
option(QUIC_ENABLE_SANITIZERS "Enables sanitizers" OFF)
option(QUIC_STATIC_LINK_CRT "Statically links the C runtime" ON)
option(QUIC_UWP_BUILD "Build for UWP" OFF)
option(QUIC_GAMECORE_BUILD "Build for GameCore" OFF)
option(QUIC_PGO "Enables profile guided optimizations" OFF)
option(QUIC_SOURCE_LINK "Enables source linking on MSVC" ON)
option(QUIC_EMBED_GIT_HASH "Embed git commit hash in the binary" ON)
option(QUIC_PDBALTPATH "Enable PDBALTPATH setting on MSVC" ON)
option(QUIC_CODE_CHECK "Run static code checkers" OFF)
option(QUIC_OPTIMIZE_LOCAL "Optimize code for local machine architecture" OFF)
option(QUIC_CI "CI Specific build" OFF)
option(QUIC_SKIP_CI_CHECKS "Disable CI specific build checks" OFF)
option(QUIC_TELEMETRY_ASSERTS "Enable telemetry asserts in release builds" OFF)
option(QUIC_USE_SYSTEM_LIBCRYPTO "Use system libcrypto if openssl TLS" OFF)
option(QUIC_HIGH_RES_TIMERS "Configure the system to use high resolution timers" OFF)
option(QUIC_SHARED_EC "Use shared execution contexts between QUIC and UDP" OFF)
option(QUIC_USE_XDP "Uses XDP instead of socket APIs" OFF)
option(QUIC_DISABLE_POSIX_GSO "Disable GSO for systems that say they support it but don't" OFF)
set(QUIC_FOLDER_PREFIX "" CACHE STRING "Optional prefix for source group folders when using an IDE generator")
set(QUIC_LIBRARY_NAME "msquic" CACHE STRING "Override the output library name")

if (QUIC_UWP_BUILD OR QUIC_GAMECORE_BUILD)
    message(STATUS "UWP And GameCore builds disable all executables, and force shared CRT")
    set(QUIC_BUILD_TOOLS OFF)
    set(QUIC_BUILD_TEST OFF)
    set(QUIC_BUILD_PERF OFF)
    set(QUIC_STATIC_LINK_CRT OFF)
endif()

if (NOT QUIC_BUILD_SHARED)
    cmake_minimum_required(VERSION 3.20)
endif()

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

include(${PROJECT_SOURCE_DIR}/cmake/GitCommands.cmake)
get_git_current_hash(${PROJECT_SOURCE_DIR} GIT_CURRENT_HASH)

if(NOT GIT_CURRENT_HASH)
    message("Failed to get git hash. Binary will not contain git hash")
    set(QUIC_SOURCE_LINK OFF)
    set(QUIC_EMBED_GIT_HASH OFF)
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
        message(WARNING "Disabling SourceLink due to old version of MSVC. Please update to VS2019 or greater!")
    endif()
endif()

set(QUIC_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(QUIC_OUTPUT_DIR ${QUIC_BUILD_DIR}/bin/$<IF:$<CONFIG:Debug>,Debug,Release> CACHE STRING "Output directory for build artifacts")

string(GENEX_STRIP ${QUIC_OUTPUT_DIR} QUIC_OUTPUT_DIR_STRIPPED)

string(COMPARE EQUAL ${QUIC_OUTPUT_DIR} ${QUIC_OUTPUT_DIR_STRIPPED} QUIC_HAS_GENERATOR_OUTPUT_DIR)

if (QUIC_HAS_GENERATOR_OUTPUT_DIR)
    set(QUIC_PGO_DIR ${QUIC_OUTPUT_DIR})
else ()
    set(QUIC_PGO_DIR ${QUIC_BUILD_DIR}/PGO)
endif ()

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
    set(QUIC_WARNING_FLAGS /WX /W4 /sdl /wd4206 CACHE INTERNAL "")
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

    include(CheckSymbolExists)
    include(CheckFunctionExists)
    include(CheckIncludeFile)
    check_symbol_exists(_SC_PHYS_PAGES unistd.h HAS__SC_PHYS_PAGES)
    check_function_exists(sysconf HAS_SYSCONF)

    if (CX_PLATFORM STREQUAL "linux")
        include(CheckCCompilerFlag)

        check_symbol_exists(UDP_SEGMENT netinet/udp.h HAS_UDP_SEGMENT)
        if (NOT HAS_UDP_SEGMENT)
            message(STATUS "UDP_SEGMENT is missing. Send performance will be reduced")
        endif()

        check_symbol_exists(SO_ATTACH_REUSEPORT_CBPF sys/socket.h HAS_SO_ATTACH_REUSEPORT_CBPF)
        if(NOT HAS_SO_ATTACH_REUSEPORT_CBPF)
            message(STATUS "SO_ATTACH_REUSEPORT_CBPF is missing. Server receive performance will be reduced")
        endif()

        check_function_exists(sendmmsg HAS_SENDMMSG)
        if(NOT HAS_SENDMMSG)
            message(STATUS "sendmmsg is missing. Send performance will be reduced")
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

        if (QUIC_ENABLE_LOGGING)
            check_include_file(lttng/ust-config.h HAS_LTTNG)
            if (NOT HAS_LTTNG)
                message(STATUS "LTTng logging not found. Disabling logging")
                set(QUIC_ENABLE_LOGGING OFF)
            endif()
        endif()

        # Check to see if lttng will work
        if(QUIC_ENABLE_LOGGING)
            check_symbol_exists(LTTNG_UST_HAVE_SDT_INTEGRATION lttng/ust-config.h HAS_LTTNG_SDT)
            if(HAS_LTTNG_SDT)
                message(WARNING "LTTng with SDT integration does not work. Disabling logging")
                set(QUIC_ENABLE_LOGGING OFF)
            endif()
        endif()

    elseif(CX_PLATFORM STREQUAL "darwin")
        check_function_exists(sysctl HAS_SYSCTL)
    endif()

    set(QUIC_COMMON_FLAGS "")
    set(QUIC_COMMON_DEFINES _GNU_SOURCE)
    if (HAS_SENDMMSG)
        list(APPEND QUIC_COMMON_DEFINES HAS_SENDMMSG)
    endif()
    if (HAS__SC_PHYS_PAGES)
         list(APPEND QUIC_COMMON_DEFINES HAS__SC_PHYS_PAGES)
    endif()
    if (HAS_SYSCONF)
         list(APPEND QUIC_COMMON_DEFINES HAS_SYSCONF)
    endif()
    if (HAS_SYSCTL)
         list(APPEND QUIC_COMMON_DEFINES HAS_SYSCTL)
    endif()
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

if (QUIC_EMBED_GIT_HASH)
    list(APPEND QUIC_COMMON_DEFINES VER_GIT_HASH=${GIT_CURRENT_HASH})
endif()

if(QUIC_TELEMETRY_ASSERTS)
    list(APPEND QUIC_COMMON_DEFINES QUIC_TELEMETRY_ASSERTS=1)
endif()

if(QUIC_HIGH_RES_TIMERS)
    list(APPEND QUIC_COMMON_DEFINES QUIC_HIGH_RES_TIMERS=1)
endif()

if(QUIC_SHARED_EC)
    list(APPEND QUIC_COMMON_DEFINES QUIC_USE_EXECUTION_CONTEXTS=1)
endif()

if(QUIC_USE_XDP)
    list(APPEND QUIC_COMMON_DEFINES QUIC_USE_EXECUTION_CONTEXTS=1 QUIC_USE_RAW_DATAPATH=1)
endif()

if(QUIC_TLS STREQUAL "schannel")
    message(STATUS "Enabling Schannel configuration tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_TEST_SCHANNEL_FLAGS=1)
    if (NOT QUIC_SHARED_EC)
        message(STATUS "Enabling UDP Send Queuing")
        list(APPEND QUIC_COMMON_DEFINES CXPLAT_DATAPATH_QUEUE_SENDS=1)
    endif()
    message(STATUS "Disabling PFX tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_PFX_TESTS)
    message(STATUS "Disabling 0-RTT support")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_0RTT_TESTS)
    message(STATUS "Disabling ChaCha20 support")
    list(APPEND QUIC_COMMON_DEFINES QUIC_DISABLE_CHACHA20_TESTS)
    message(STATUS "Enabling anonymous client auth tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_ENABLE_ANON_CLIENT_AUTH_TESTS)
endif()

if(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Enabling OpenSsl configuration tests")
    list(APPEND QUIC_COMMON_DEFINES QUIC_TEST_OPENSSL_FLAGS=1)
endif()

if(WIN32)
    if (CMAKE_GENERATOR_PLATFORM STREQUAL "")
        string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} SYSTEM_PROCESSOR)
    else()
        string(TOLOWER ${CMAKE_GENERATOR_PLATFORM} SYSTEM_PROCESSOR)
    endif()

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
        list(APPEND QUIC_COMMON_DEFINES QUIC_UWP_BUILD QUIC_RESTRICTED_BUILD)
        set(CMAKE_CXX_STANDARD_LIBRARIES "")
        set(CMAKE_CXX_STANDARD_LIBRARIES_INIT "")
        set(CMAKE_C_STANDARD_LIBRARIES "")
        set(CMAKE_C_STANDARD_LIBRARIES_INIT "")
    endif()

    if (QUIC_GAMECORE_BUILD)
        list(APPEND QUIC_COMMON_DEFINES WINAPI_FAMILY=WINAPI_FAMILY_GAMES QUIC_GAMECORE_BUILD QUIC_RESTRICTED_BUILD)
        set(CMAKE_CXX_STANDARD_LIBRARIES "")
        set(CMAKE_CXX_STANDARD_LIBRARIES_INIT "")
        set(CMAKE_C_STANDARD_LIBRARIES "")
        set(CMAKE_C_STANDARD_LIBRARIES_INIT "")

        set(UnsupportedLibs advapi32.lib comctl32.lib comsupp.lib dbghelp.lib gdi32.lib gdiplus.lib guardcfw.lib kernel32.lib mmc.lib msimg32.lib msvcole.lib msvcoled.lib mswsock.lib ntstrsafe.lib ole2.lib ole2autd.lib ole2auto.lib ole2d.lib ole2ui.lib ole2uid.lib ole32.lib oleacc.lib oleaut32.lib oledlg.lib oledlgd.lib oldnames.lib runtimeobject.lib shell32.lib shlwapi.lib strsafe.lib urlmon.lib user32.lib userenv.lib wlmole.lib wlmoled.lib onecore.lib)
        set(Console_LinkOptions /DYNAMICBASE /NXCOMPAT)
        foreach(arg ${UnsupportedLibs})
            list(APPEND Console_LinkOptions "/NODEFAULTLIB:${arg}")
        endforeach()

        set(Console_ArchOptions /favor:AMD64)

        list(APPEND Console_ArchOptions /arch:AVX)

        # Locate Software Development Kits
        get_filename_component(Console_SdkRoot "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\GDK;InstallPath]" ABSOLUTE CACHE)

        if(NOT EXISTS ${Console_SdkRoot})
            if (EXISTS "C:\\Program Files (x86)\\Microsoft GDK")
                set(Console_SdkRoot "C:\\Program Files (x86)\\Microsoft GDK")
            else()
                message(FATAL_ERROR "Could not find GDK install")
            endif()
        endif()

        file(GLOB GdkFolders ${Console_SdkRoot}/*)

        set(XdkEditionTarget 5000000000)

        foreach(GdkFolder ${GdkFolders})
            if (IS_DIRECTORY ${GdkFolder})
                file(GLOB SubDirs ${GdkFolder}/*)
                foreach(SubDir ${SubDirs})
                    if (SubDir MATCHES "GXDK$")
                        # Make sure library exists
                        set(GxdkLibDirectory "${SubDir}/gameKit/Lib/amd64")
                        set(GxdkRuntimeLib "${GxdkLibDirectory}/xgameplatform.lib")
                        if (EXISTS ${GxdkRuntimeLib})
                            get_filename_component(PotentialXdkEditionTarget ${GdkFolder} NAME)
                            # Always select lowest version equal or higher than 211000
                            if (PotentialXdkEditionTarget LESS XdkEditionTarget AND
                                PotentialXdkEditionTarget GREATER_EQUAL 211000)
                                set(XdkEditionTarget ${PotentialXdkEditionTarget})
                                set(Console_EndpointLibRoot "${GxdkLibDirectory}")
                            endif()
                        endif()
                    endif()
                endforeach()
            endif()
        endforeach()

        if (XdkEditionTarget EQUAL 5000000000)
            message(FATAL_ERROR "Gxdk Target Not Found")
        endif()

        message(STATUS "Chosing ${XdkEditionTarget} with root ${Console_EndpointLibRoot}")

    endif()

    if(QUIC_ENABLE_LOGGING)
        message(STATUS "Configuring for manifested ETW tracing")
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_MANIFEST_ETW QUIC_LOGS_MANIFEST_ETW)
    else()
        message(STATUS "QUIC_ENABLE_LOGGING is false. Disabling logging")
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
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")

    # Find the right PGO file.
    if(QUIC_SHARED_EC)
        set(QUIC_PGO_NAME "msquic.${QUIC_TLS}.sharedec.pgd")
        set(QUIC_PGO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/bin/winuser/pgo_${SYSTEM_PROCESSOR}/${QUIC_PGO_NAME}")
    endif()
    if(NOT EXISTS "${QUIC_PGO_FILE}")
        set(QUIC_PGO_NAME "msquic.${QUIC_TLS}.pgd")
        set(QUIC_PGO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/bin/winuser/pgo_${SYSTEM_PROCESSOR}/${QUIC_PGO_NAME}")
    endif()
    if(NOT EXISTS "${QUIC_PGO_FILE}")
        set(QUIC_PGO_NAME "msquic.pgd")
        set(QUIC_PGO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/bin/winuser/pgo_${SYSTEM_PROCESSOR}/${QUIC_PGO_NAME}")
    endif()
    message(STATUS "Using PGO file ${QUIC_PGO_NAME}")

    # Configure PGO linker flags.
    if(QUIC_PGO)
        # Configured for training mode. Use the previous PGD file if present.
        if(EXISTS "${QUIC_PGO_FILE}")
            message(STATUS "/GENPROFILE:PDG")
            configure_file("${QUIC_PGO_FILE}" "${QUIC_PGO_DIR}/msquic.pgd" COPYONLY)
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /GENPROFILE:\"PGD=${QUIC_PGO_DIR}/msquic.pgd\"")
        else()
            message(STATUS "/GENPROFILE")
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /GENPROFILE")
        endif()
        set(CMAKE_VS_SDK_LIBRARY_DIRECTORIES "$(LibraryPath);$(VC_LibraryPath_VC_${SYSTEM_PROCESSOR}_Desktop)")
    else()
        # Just doing a normal build. Use the PGD file if present.
        if(EXISTS "${QUIC_PGO_FILE}")
            message(STATUS "Using profile-guided optimization")
            file(MAKE_DIRECTORY ${QUIC_PGO_DIR})
            configure_file("${QUIC_PGO_FILE}" "${QUIC_PGO_DIR}/msquic.pgd" COPYONLY)
            set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /USEPROFILE:\"PGD=${QUIC_PGO_DIR}/msquic.pgd\"")
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

    set(CMAKE_C_FLAGS_DEBUG "-Og")
    set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 ${MARCH} -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O3 ${MARCH} -DNDEBUG")
    if (CX_PLATFORM STREQUAL "darwin")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -gdwarf")
        set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -gdwarf")
    else()
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb3")
        set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -ggdb3")
    endif()
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
            set (QUIC_LINUX_LOGGING_METHOD linux)
            include(FindLTTngUST)
        endif()
    else()
        message(STATUS "QUIC_ENABLE_LOGGING is false. Disabling logging")
        list(APPEND QUIC_COMMON_DEFINES QUIC_EVENTS_STUB QUIC_LOGS_STUB)
    endif()

    if(QUIC_ENABLE_SANITIZERS)
        message(STATUS "Configuring sanitizers")
        list(APPEND QUIC_COMMON_FLAGS -fsanitize=address,leak,undefined,alignment -fsanitize-address-use-after-scope -Og -fno-omit-frame-pointer -fno-optimize-sibling-calls)
        if (CX_PLATFORM STREQUAL "darwin")
            list(APPEND QUIC_COMMON_FLAGS -gdwarf)
        else()
            list(APPEND QUIC_COMMON_FLAGS -ggdb3)
        endif()
        if (CMAKE_C_COMPILER_ID MATCHES "Clang")
            list(APPEND QUIC_COMMON_FLAGS -fsanitize=unsigned-integer-overflow -fsanitize=local-bounds -fsanitize=integer -fsanitize=nullability)
        endif()
    endif()

    set(QUIC_C_FLAGS ${QUIC_COMMON_FLAGS})
    set(QUIC_CXX_FLAGS ${QUIC_COMMON_FLAGS})
endif()

if(QUIC_TLS STREQUAL "openssl")
    add_library(OpenSSL INTERFACE)

    include(FetchContent)

    FetchContent_Declare(
        OpenSSLQuic
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/submodules
        CMAKE_ARGS "-DQUIC_USE_SYSTEM_LIBCRYPTO=${QUIC_USE_SYSTEM_LIBCRYPTO}"
    )
    FetchContent_MakeAvailable(OpenSSLQuic)

    target_link_libraries(OpenSSL
        INTERFACE
        OpenSSLQuic::OpenSSLQuic
    )
endif()

if(QUIC_CODE_CHECK)
    find_program(CLANGTIDY NAMES clang-tidy)
    if(CLANGTIDY)
        message(STATUS "Found clang-tidy: ${CLANGTIDY}")
        set(CLANG_TIDY_CHECKS *
            # add checks to ignore here:
            -altera-*
            -android-cloexec-fopen
            -android-cloexec-socket
            -bugprone-easily-swappable-parameters
            -bugprone-implicit-widening-of-multiplication-result
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
            --suppress=varFuncNullUB --suppress=constParameter
            # these are finding potential logic issues, may want to suppress when focusing on nits:
            --suppress=nullPointer --suppress=nullPointerRedundantCheck
            --suppress=knownConditionTrueFalse --suppress=invalidscanf
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
