# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include_directories(${CMAKE_SOURCE_DIR}/src/platform)
include_directories(${CMAKE_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

# Include Files that need CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})

set(
    SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

#
# Setup CLOG by calling a helper function which sets up dependencies.  Then add the .c file
#     ...it'd be preferred to have the helper function set this requirement
#
CLOG_ADD_SOURCEFILE(MSQUIC_PLATFORMTEST ${SOURCES})

add_executable(msquicplatformtest ${SOURCES})

if(WIN32)
    target_link_libraries(msquicplatformtest ntdll ws2_32 bcrypt advapi32)
endif()

if(QUIC_TLS STREQUAL "schannel")
    target_link_libraries(msquicplatformtest schannel ncrypt crypt32)
elseif(QUIC_TLS STREQUAL "openssl")
    add_dependencies(msquicplatformtest OpenSSL)
    target_link_libraries(msquicplatformtest
        ${QUIC_BUILD_DIR}/openssl/lib/libcrypto.so
        ${QUIC_BUILD_DIR}/openssl/lib/libssl.so)
elseif(QUIC_TLS STREQUAL "mitls")
    target_link_libraries(msquicplatformtest kremlib evercrypt mitls quiccrypto ncrypt crypt32)
endif()

target_link_libraries(msquicplatformtest platform gtest MSQUIC_PLATFORMTEST)

add_test(msquicplatformtest msquicplatformtest)
