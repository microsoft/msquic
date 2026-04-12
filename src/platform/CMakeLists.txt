# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

set(SOURCES crypt.c hashtable.c pcp.c platform_worker.c toeplitz.c)

if("${CX_PLATFORM}" STREQUAL "windows")
    set(SOURCES ${SOURCES} platform_winuser.c storage_winuser.c datapath_win.c datapath_winuser.c datapath_xplat.c)
    if(QUIC_UWP_BUILD OR
       QUIC_GAMECORE_BUILD OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm" OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm64" OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm64ec")
        set(SOURCES ${SOURCES} datapath_raw_dummy.c)
    else()
        set(SOURCES ${SOURCES} datapath_raw.c datapath_raw_win.c datapath_raw_socket.c datapath_raw_socket_win.c datapath_raw_xdp_win.c)
    endif()
else()
    set(SOURCES ${SOURCES} platform_posix.c storage_posix.c cgroup.c datapath_unix.c)
    if(CX_PLATFORM STREQUAL "linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(SOURCES ${SOURCES} datapath_linux.c)
        if (QUIC_LINUX_IOURING_ENABLED)
            set(SOURCES ${SOURCES} datapath_iouring.c)
        else()
            set(SOURCES ${SOURCES} datapath_epoll.c)
        endif()
        set(SOURCES ${SOURCES} datapath_xplat.c datapath_raw_dummy.c)
    else()
        set(SOURCES ${SOURCES} datapath_kqueue.c)
    endif()

    # Compile for Android failed by __atomic_add_fetch(), only emulator and some old ChromeBooks are X86, so the performance penalty may be acceptable, do not patch all the atomic usage for now
    # > error: misaligned atomic operation may incur significant performance penalty; the expected alignment (8 bytes) exceeds the actual alignment (4 bytes)
    if (ANDROID AND ANDROID_ABI STREQUAL "x86")
        add_compile_options(-Wno-atomic-alignment)
    endif()
endif()

if (QUIC_TLS_LIB STREQUAL "schannel")
    message(STATUS "Configuring for Schannel")
    set(SOURCES ${SOURCES} cert_capi.c crypt_bcrypt.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS_LIB STREQUAL "quictls" OR QUIC_TLS_LIB STREQUAL "openssl")
    if (QUIC_TLS_LIB STREQUAL "quictls")
        message(STATUS "Configuring for QuicTLS")
        set(SOURCES ${SOURCES} tls_quictls.c crypt_openssl.c)
    else()
        message(STATUS "Configuring for OpenSSL")
        set(SOURCES ${SOURCES} tls_openssl.c crypt_openssl.c)
    endif()
    if ("${CX_PLATFORM}" STREQUAL "windows")
        set(SOURCES ${SOURCES} certificates_capi.c cert_capi.c  selfsign_capi.c)
    elseif(CX_PLATFORM STREQUAL "linux")
        set(SOURCES ${SOURCES} certificates_posix.c selfsign_openssl.c)
    else()
        set(SOURCES ${SOURCES} certificates_darwin.c selfsign_openssl.c)
    endif()
else()
    message(FATAL_ERROR "TLS Provider not configured")
endif()

add_library(msquic_platform STATIC ${SOURCES})
add_library(msquic::platform ALIAS msquic_platform)
set_target_properties(msquic_platform PROPERTIES EXPORT_NAME platform)

if("${CX_PLATFORM}" STREQUAL "windows")
    target_link_libraries(
        msquic_platform
        PUBLIC
        wbemuuid)
    target_link_libraries(msquic_platform PUBLIC winmm)
endif()

if (QUIC_USE_EXTERNAL_OPENSSL AND NOT BUILD_SHARED_LIBS)
    find_library(LIB_Z NAMES "z${CMAKE_STATIC_LIBRARY_SUFFIX}" "libz${CMAKE_STATIC_LIBRARY_SUFFIX}")
    find_library(LIB_ZSTD NAMES "zstd${CMAKE_STATIC_LIBRARY_SUFFIX}" "libzstd${CMAKE_STATIC_LIBRARY_SUFFIX}")
    target_link_libraries(msquic_platform PUBLIC ${LIB_Z} ${LIB_ZSTD})
endif()

target_link_libraries(msquic_platform PUBLIC inc)
target_link_libraries(msquic_platform PRIVATE warnings main_binary_link_args)

set_property(TARGET msquic_platform PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

if ("${CX_PLATFORM}" STREQUAL "windows")
    target_include_directories(
        msquic_platform
        PRIVATE
        ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES}
        ${PROJECT_SOURCE_DIR}/submodules/xdp-for-windows/published/external)
else()
    target_include_directories(msquic_platform PRIVATE ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES})
endif()

if (MSVC AND (QUIC_TLS_LIB STREQUAL "quictls" OR QUIC_TLS_LIB STREQUAL "schannel") AND NOT QUIC_SANITIZER_ACTIVE)
    target_compile_options(msquic_platform PRIVATE /analyze)
endif()

if(QUIC_TLS_LIB STREQUAL "quictls" OR QUIC_TLS_LIB STREQUAL "openssl")
    target_link_libraries(msquic_platform PUBLIC OpenSSL)
    if (CX_PLATFORM STREQUAL "darwin")
        target_link_libraries(msquic_platform PUBLIC "-framework CoreFoundation" "-framework Security")
    endif()
elseif(QUIC_TLS_LIB STREQUAL "schannel")
    target_link_libraries(msquic_platform PUBLIC secur32)
    if (NOT QUIC_GAMECORE_BUILD)
        target_link_libraries(msquic_platform PUBLIC onecore)
    endif()
endif()
