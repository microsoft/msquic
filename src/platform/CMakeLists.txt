# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

set(SOURCES
    crypt.c
    hashtable.c
    pcp.c
    toeplitz.c
    )

if("${CX_PLATFORM}" STREQUAL "windows")
    set(SOURCES ${SOURCES} datapath_winuser.c platform_winuser.c storage_winuser.c)
else()
    if(CX_PLATFORM STREQUAL "linux")
        set(SOURCES ${SOURCES} datapath_epoll.c platform_posix.c storage_posix.c)
    else()
        set(SOURCES ${SOURCES} datapath_kqueue.c platform_posix.c storage_posix.c)
    endif()
endif()

if (QUIC_TLS STREQUAL "schannel")
    message(STATUS "Configuring for Schannel")
    set(SOURCES ${SOURCES} cert_capi.c crypt_bcrypt.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} tls_openssl.c cert_capi_openssl.c)
    if ("${CX_PLATFORM}" STREQUAL "windows")
        set(SOURCES ${SOURCES} cert_capi.c crypt_bcrypt.c selfsign_capi.c)
    else()
        set(SOURCES ${SOURCES} crypt_openssl.c selfsign_openssl.c)
    endif()
else()
    message(FATAL_ERROR "TLS Provider not configured")
endif()

# Allow CLOG to preprocess all the source files.
add_clog_library(platform.clog DYNAMIC ${SOURCES})
if(QUIC_ENABLE_LOGGING)
    set_property(TARGET platform.clog.provider PROPERTY FOLDER "helpers")
endif()

add_library(platform STATIC ${SOURCES})

target_link_libraries(platform PUBLIC platform.clog inc)

target_link_libraries(platform PRIVATE warnings)

set_property(TARGET platform PROPERTY FOLDER "libraries")

target_include_directories(platform PRIVATE ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES})

if (MSVC AND (QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "schannel") AND NOT QUIC_ENABLE_SANITIZERS)
    target_compile_options(platform PRIVATE /analyze)
endif()

if(QUIC_TLS STREQUAL "openssl")
    target_link_libraries(platform PUBLIC OpenSSL)
elseif(QUIC_TLS STREQUAL "schannel")
    target_link_libraries(platform PUBLIC secur32)
endif()
