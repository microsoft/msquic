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
    set(SOURCES ${SOURCES} platform_winuser.c storage_winuser.c)
    if(QUIC_USE_XDP)
        set(SOURCES ${SOURCES} datapath_raw.c datapath_raw_socket.c datapath_raw_xdp.c)
    else()
        set(SOURCES ${SOURCES} datapath_winuser.c)
    endif()
else()
    set(SOURCES ${SOURCES} inline.c platform_posix.c storage_posix.c cgroup.c)
    if(CX_PLATFORM STREQUAL "linux")
        set(SOURCES ${SOURCES} datapath_epoll.c)
    else()
        set(SOURCES ${SOURCES} datapath_kqueue.c)
    endif()
endif()

if (QUIC_TLS STREQUAL "schannel")
    message(STATUS "Configuring for Schannel")
    set(SOURCES ${SOURCES} cert_capi.c crypt_bcrypt.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} tls_openssl.c crypt_openssl.c)
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

add_library(platform STATIC ${SOURCES})

if(QUIC_USE_XDP)
    target_link_libraries(
        platform
        PUBLIC
        inc
        wbemuuid
        ${PROJECT_SOURCE_DIR}/artifacts/xdp/lib/xdpapi.lib)
else()
    target_link_libraries(platform PUBLIC inc)
endif()

if("${CX_PLATFORM}" STREQUAL "windows")
    target_link_libraries(platform PUBLIC winmm)
endif()

target_link_libraries(platform PRIVATE warnings main_binary_link_args)

set_property(TARGET platform PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

if(QUIC_USE_XDP)
    target_include_directories(
        platform
        PRIVATE
        ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES}
        ${PROJECT_SOURCE_DIR}/artifacts/xdp/include)
else()
    target_include_directories(platform PRIVATE ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES})
endif()

if (MSVC AND (QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "schannel") AND NOT QUIC_ENABLE_SANITIZERS)
    target_compile_options(platform PRIVATE /analyze)
endif()

if(QUIC_TLS STREQUAL "openssl")
    target_link_libraries(platform PUBLIC OpenSSL)
    if (CX_PLATFORM STREQUAL "darwin")
        target_link_libraries(platform PUBLIC "-framework CoreFoundation" "-framework Security")
    endif()
elseif(QUIC_TLS STREQUAL "schannel")
    target_link_libraries(platform PUBLIC secur32 onecore)
endif()
