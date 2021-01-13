# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

if("${CX_PLATFORM}" STREQUAL "windows")
    set(SOURCES
        datapath_winuser.c
        hashtable.c
        platform_winuser.c
        storage_winuser.c
        toeplitz.c
    )
else()
    if(CX_PLATFORM STREQUAL "linux")
        set(SOURCES
            datapath_epoll.c
            hashtable.c
            inline.c
            platform_posix.c
            storage_posix.c
            toeplitz.c
        )
    else()
        set(SOURCES
            datapath_kqueue.c
            hashtable.c
            inline.c
            platform_posix.c
            storage_posix.c
            toeplitz.c
        )
    endif()
endif()

if (QUIC_TLS STREQUAL "schannel")
    message(STATUS "Configuring for SChannel")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} tls_openssl.c cert_capi_openssl.c)
    if ("${CX_PLATFORM}" STREQUAL "windows")
        set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c)
    else()
        set(SOURCES ${SOURCES} selfsign_openssl.c)
    endif()
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
