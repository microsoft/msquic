# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

set(SOURCES crypt.c hashtable.c pcp.c toeplitz.c)

if(QUIC_USE_DPDK)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/datapath_dpdk_clang.o
        COMMAND clang ${CMAKE_CURRENT_SOURCE_DIR}/datapath_dpdk_clang.c -I${PROJECT_SOURCE_DIR}/src/inc -I${PROJECT_SOURCE_DIR}/artifacts/dpdk/include -DQUIC_EVENTS_MANIFEST_ETW -DQUIC_LOGS_MANIFEST_ETW -I${QUIC_BUILD_DIR}/inc -o datapath_dpdk_clang.o -c -msse4
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/datapath_dpdk.c_clang
        DEPENDS MsQuicEtw_HeaderBuild
    )
endif()

if("${CX_PLATFORM}" STREQUAL "windows")
    set(SOURCES ${SOURCES} platform_winuser.c storage_winuser.c)
    if(QUIC_USE_DPDK)
        set(SOURCES ${SOURCES} datapath_dpdk.c ${CMAKE_CURRENT_BINARY_DIR}/datapath_dpdk_clang.o)
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
        set(SOURCES ${SOURCES} cert_capi_openssl.c cert_capi.c  selfsign_capi.c)
    elseif(CX_PLATFORM STREQUAL "linux")
        set(SOURCES ${SOURCES} posix_openssl.c selfsign_openssl.c)
    else()
        set(SOURCES ${SOURCES} darwin_openssl.c selfsign_openssl.c)
    endif()
else()
    message(FATAL_ERROR "TLS Provider not configured")
endif()

add_library(platform STATIC ${SOURCES})

if(QUIC_USE_DPDK)
    target_link_libraries(
        platform
        PUBLIC
        inc
        ${PROJECT_SOURCE_DIR}/artifacts/dpdk/lib/rte_eal.lib
        ${PROJECT_SOURCE_DIR}/artifacts/dpdk/lib/rte_ethdev.lib
        ${PROJECT_SOURCE_DIR}/artifacts/dpdk/lib/rte_mbuf.lib
        ${PROJECT_SOURCE_DIR}/artifacts/dpdk/lib/rte_mempool.lib)
else()
    target_link_libraries(platform PUBLIC inc)
endif()

target_link_libraries(platform PRIVATE warnings)

set_property(TARGET platform PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

if(QUIC_USE_DPDK)
    target_include_directories(
        platform
        PRIVATE
        ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES}
        ${PROJECT_SOURCE_DIR}/artifacts/dpdk/include)
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
    target_link_libraries(platform PUBLIC secur32)
endif()
