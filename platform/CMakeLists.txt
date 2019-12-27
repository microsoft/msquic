# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include Files that need CLOG processing
include("../CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})

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
    message(STATUS "Configuring for SChannel")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} selfsign_openssl.c tls_openssl.c)
    include_directories(${CMAKE_SOURCE_DIR}/bld/openssl/include)
elseif(QUIC_TLS STREQUAL "mitls")
    message(STATUS "Configuring for miTLS")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_mitls.c)
    include_directories(${CMAKE_SOURCE_DIR}/submodules/everest/msquic/msvc/include)
else()
    message(STATUS "Configuring for stub TLS")
    set(SOURCES ${SOURCES} cert_stub.c selfsign_stub.c tls_stub.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS}")

#
# Setup CLOG by calling a helper function which sets up dependencies.  Then add the .c file
#     ...it'd be preferred to have the helper function set this requirement
#
CLOG_ADD_SOURCEFILE(SOURCES ${SOURCES})


add_library(platform STATIC ${SOURCES})

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
else()
    target_link_libraries(platform ${LTTNGUST_LIBRARIES})
endif()

if(QUIC_TLS STREQUAL "openssl")
    add_dependencies(platform OpenSSL)
    target_link_libraries(platform
        ${CMAKE_SOURCE_DIR}/bld/openssl/lib/libcrypto.so
        ${CMAKE_SOURCE_DIR}/bld/openssl/lib/libssl.so)
elseif(QUIC_TLS STREQUAL "mitls")
    target_link_libraries(platform kremlib evercrypt mitls quiccrypto)
endif()
