# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
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
    include_directories(${QUIC_BUILD_DIR}/openssl/include)
elseif(QUIC_TLS STREQUAL "mitls")
    message(STATUS "Configuring for miTLS")
    set(SOURCES ${SOURCES} cert_capi.c selfsign_capi.c tls_mitls.c)
    include_directories(${PROJECT_SOURCE_DIR}/submodules/everest/msquic/msvc/include)
else()
    message(STATUS "Configuring for stub TLS")
    set(SOURCES ${SOURCES} cert_stub.c selfsign_stub.c tls_stub.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS}")

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(PLATFORM_CLOG_LIB ${SOURCES})

add_library(platform STATIC ${SOURCES})

set_property(TARGET platform PROPERTY FOLDER "libraries")

target_compile_options(platform PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

if(QUIC_ENABLE_LOGGING)
    if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        add_dependencies(platform MsQuicEtw)
    else()
        target_link_libraries(platform ${LTTNGUST_LIBRARIES})
    endif()
endif()

if(QUIC_TLS STREQUAL "openssl")
    add_dependencies(platform OpenSSL)
    target_link_libraries(platform
        ${QUIC_BUILD_DIR}/openssl/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
        ${QUIC_BUILD_DIR}/openssl/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})
elseif(QUIC_TLS STREQUAL "mitls")
    target_link_libraries(platform kremlib evercrypt mitls quiccrypto)
endif()

if (NOT MSVC AND NOT APPLE)
    find_library(ATOMIC NAMES atomic libatomic.so.1)
    if (ATOMIC)
        message(STATUS "Found libatomic: ${ATOMIC}")
    endif()
endif()

target_link_libraries(platform ${ATOMIC})
