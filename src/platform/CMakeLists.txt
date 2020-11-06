# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if("${QUIC_PLATFORM}" STREQUAL "windows")
    set(SOURCES
        datapath_winuser.c
        hashtable.c
        platform_winuser.c
        storage_winuser.c
        toeplitz.c
    )
else()
    if(QUIC_PLATFORM STREQUAL "linux")
        set(SOURCES
            datapath_linux.c
            hashtable.c
            inline.c
            platform_linux.c
            storage_linux.c
            toeplitz.c
        )
    else()
        set(SOURCES
            datapath_darwin.c
            hashtable.c
            inline.c
            platform_darwin.c
            storage_darwin.c
            toeplitz.c
        )
    endif()
endif()

if (QUIC_TLS STREQUAL "schannel")
    message(STATUS "Configuring for SChannel")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} selfsign_openssl.c tls_openssl.c)
elseif(QUIC_TLS STREQUAL "mitls")
    message(STATUS "Configuring for miTLS")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_mitls.c)
    set(EXTRA_PLATFORM_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/submodules/everest/msquic/msvc/include)
else()
    message(STATUS "Configuring for stub TLS")
    set(SOURCES ${SOURCES} cert_stub.c selfsign_stub.c tls_stub.c)
endif()

# Allow CLOG to preprocess all the source files.
add_clog_library(platform.clog DYNAMIC ${SOURCES})

add_library(platform STATIC ${SOURCES})

target_link_libraries(platform PUBLIC platform.clog inc)

target_link_libraries(platform PRIVATE warnings)

set_property(TARGET platform PROPERTY FOLDER "libraries")

target_include_directories(platform PRIVATE ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES})

if(QUIC_TLS STREQUAL "openssl")
    target_link_libraries(platform PUBLIC OpenSSL)
elseif(QUIC_TLS STREQUAL "mitls")
    target_link_libraries(platform PUBLIC kremlib evercrypt mitls quiccrypto)
endif()
