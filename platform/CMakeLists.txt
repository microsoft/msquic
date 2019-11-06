# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(SOURCES
        datapath_winuser.c
        hashtable.c
        platform_winuser.c
        storage_winuser.c
    )
else()
    set(SOURCES
        datapath_linux.c
        hashtable.c
        inline.c
        platform_linux.c
        storage_linux.c
    )
endif()

if (QUIC_TLS STREQUAL "schannel")
    message("-- Configuring SChannel")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl")
    message("-- Configuring OpenSSL")
    set(SOURCES ${SOURCES} selfsign_openssl.c tls_openssl.c)
elseif(QUIC_TLS STREQUAL "mitls")
    message("-- Configuring miTLS")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_mitls.c)
else()
    message("-- Configuring stub TLS")
    set(SOURCES ${SOURCES} cert_stub.c selfsign_stub.c tls_stub.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS}")

add_library(platform STATIC ${SOURCES})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
endif()

if(QUIC_TLS STREQUAL "openssl")
    add_dependencies(platform OpenSSL)
endif()
