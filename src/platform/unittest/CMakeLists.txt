# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include for CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")

include_directories(${PROJECT_SOURCE_DIR}/src/platform)
include_directories(${PROJECT_SOURCE_DIR}/submodules/googletest/googletest/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

# Allow CLOG to preprocess all the source files.
CLOG_GENERATE_TARGET(MSQUIC_PLATFORMTEST ${SOURCES})

add_executable(msquicplatformtest ${SOURCES})

set_property(TARGET msquicplatformtest PROPERTY FOLDER "tests")

if(WIN32)
    target_link_libraries(msquicplatformtest ntdll ws2_32 bcrypt advapi32)
endif()

if(QUIC_TLS STREQUAL "schannel")
    target_link_libraries(msquicplatformtest schannel ncrypt crypt32)
elseif(QUIC_TLS STREQUAL "openssl")
    add_dependencies(msquicplatformtest OpenSSL)
    target_link_libraries(msquicplatformtest
        ${QUIC_BUILD_DIR}/openssl/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX}
        ${QUIC_BUILD_DIR}/openssl/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})
elseif(QUIC_TLS STREQUAL "mitls")
    target_link_libraries(msquicplatformtest kremlib evercrypt mitls quiccrypto ncrypt crypt32)
endif()

target_link_libraries(msquicplatformtest msquic platform gtest MSQUIC_PLATFORMTEST PLATFORM_CLOG_LIB CORE_CLOG_LIB)

add_test(msquicplatformtest msquicplatformtest)
