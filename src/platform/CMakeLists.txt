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
    message(STATUS "Configuring for SChannel")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} selfsign_openssl.c tls_openssl.c)
    include_directories(${QUIC_BUILD_DIR}/openssl/include)
elseif(QUIC_TLS STREQUAL "mitls")
    message(STATUS "Configuring for miTLS")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_mitls.c)
    include_directories(${CMAKE_SOURCE_DIR}/submodules/everest/msquic/msvc/include)
else()
    message(STATUS "Configuring for stub TLS")
    set(SOURCES ${SOURCES} cert_stub.c selfsign_stub.c tls_stub.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS}")

add_library(platform STATIC ${SOURCES})
target_compile_options(platform PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        -Werror -Wall -Wextra -Wformat=2 -Wno-type-limits -Wno-unknown-pragmas -Wno-unused-value>
     $<$<CXX_COMPILER_ID:MSVC>:
        /WX /W4 /sdl>)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_dependencies(platform MsQuicEtw)
else()
    target_link_libraries(platform ${LTTNGUST_LIBRARIES})
endif()

if(QUIC_TLS STREQUAL "openssl")
    add_dependencies(platform OpenSSL)
    target_link_libraries(platform
        ${QUIC_BUILD_DIR}/openssl/lib/libcrypto.so
        ${QUIC_BUILD_DIR}/openssl/lib/libssl.so)
elseif(QUIC_TLS STREQUAL "mitls")
    target_link_libraries(platform kremlib evercrypt mitls quiccrypto)
endif()
