# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.16)

# This is a helper project to build OpenSSL as part of the CMake "superbuild"
# pattern, which sidesteps issues managing a dependency graph within a single
# CMake project and enables smoother developer workflows.

# This file is intended to be included in the parent msquic project via FetchContent
project(OpenSSLQuic)

set(QUIC_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
option(QUIC_USE_SYSTEM_LIBCRYPTO "Use system libcrypto if quictls TLS" OFF)

if(QUIC_TLS_LIB STREQUAL "quictls" OR QUIC_TLS_LIB STREQUAL "openssl")
    message(STATUS "Configuring for OpenSSL 3.x")
    set(EXPECTED_OPENSSL_VERSION 3.0)
    if(QUIC_TLS_LIB STREQUAL "quictls")
        set(QUIC_OPENSSL quictls)
    else()
        set(QUIC_OPENSSL openssl)
    endif()
else()
    message(FATAL_ERROR "Unsupported QUIC_TLS_LIB ${QUIC_TLS_LIB}")
endif()

set(OPENSSL_DIR ${QUIC_BUILD_DIR}/${QUIC_OPENSSL})

set(OPENSSL_CONFIG_FLAGS
    enable-tls1_3 no-makedepend no-dgram no-ssl3 no-psk no-srp

    no-zlib no-egd no-idea no-rc5 no-rc4 no-afalgeng
    no-comp no-cms no-ct no-srp no-srtp no-ts no-gost no-dso no-ec2m
    no-tls1 no-tls1_1 no-tls1_2 no-dtls no-dtls1 no-dtls1_2 no-ssl
    no-ssl3-method no-tls1-method no-tls1_1-method no-tls1_2-method no-dtls1-method no-dtls1_2-method
    no-siphash no-whirlpool no-aria no-bf no-blake2 no-sm2 no-sm3 no-sm4 no-camellia no-cast no-md4 no-mdc2 no-ocb no-rc2 no-rmd160 no-scrypt no-seed
    no-weak-ssl-ciphers no-shared no-tests
    no-uplink no-cmp no-fips no-padlockeng no-siv no-legacy no-dtls no-deprecated --libdir=lib)

if (WIN32)

    if (DEFINED ENV{CommonProgramFiles})
        message(STATUS "Setting openssldir to $ENV{CommonProgramFiles}\\SSL")
        list(APPEND OPENSSL_CONFIG_FLAGS --openssldir=\"$ENV{CommonProgramFiles}\\SSL\")
    endif()

    set(LIBSSL_DEBUG_PATH ${OPENSSL_DIR}/debug/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(LIBCRYPTO_DEBUG_PATH ${OPENSSL_DIR}/debug/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(LIBSSL_PATH ${OPENSSL_DIR}/release/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(LIBCRYPTO_PATH ${OPENSSL_DIR}/release/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})

    if (QUIC_UWP_BUILD)
        # Translate target architecture into corresponding OpenSSL build flag
        if (${SYSTEM_PROCESSOR} STREQUAL "arm64")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN64-ARM")
        elseif (${SYSTEM_PROCESSOR} STREQUAL "arm")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN32-ARM")
        elseif (${SYSTEM_PROCESSOR} STREQUAL "win32" OR ${SYSTEM_PROCESSOR} STREQUAL "x86")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN32-ONECORE")
        elseif (${SYSTEM_PROCESSOR} STREQUAL "x64" OR ${SYSTEM_PROCESSOR} STREQUAL "amd64")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN64A-ONECORE")
        else()
            message(FATAL_ERROR "Unknown Generator Platform ${SYSTEM_PROCESSOR}")
        endif()
    else()
        # Translate target architecture into corresponding OpenSSL build flag
        if (${SYSTEM_PROCESSOR} STREQUAL "arm64")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN64-ARM")
        elseif (${SYSTEM_PROCESSOR} STREQUAL "arm")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN32-ARM")
        elseif (${SYSTEM_PROCESSOR} STREQUAL "win32" OR ${SYSTEM_PROCESSOR} STREQUAL "x86")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN32")
        elseif (${SYSTEM_PROCESSOR} STREQUAL "x64" OR ${SYSTEM_PROCESSOR} STREQUAL "amd64")
            set(QUIC_OPENSSL_WIN_ARCH "VC-WIN64A")
        else()
            message(FATAL_ERROR "Unknown Generator Platform ${SYSTEM_PROCESSOR}")
        endif()
    endif()

    set(OPENSSL_EXTRA_CONFIGURE_ARGS "")

    if(HAS_SPECTRE)
        list(APPEND OPENSSL_EXTRA_CONFIGURE_ARGS /Qspectre)
    endif()

    # guard:cf does not work on OpenSSL
    # https://github.com/openssl/openssl/issues/16147
    # if(HAS_GUARDCF)
    #     list(APPEND OPENSSL_EXTRA_CONFIGURE_ARGS /guard:cf)
    # endif()

    find_program(JOM_EXE jom)
    if (JOM_EXE)
        list(APPEND OPENSSL_EXTRA_CONFIGURE_ARGS /FS)
        include(ProcessorCount)
        ProcessorCount(NPROCS)
        set(OPENSSL_RUN_COMMAND "${JOM_EXE}" -j${NPROCS})
    else()

        set(OPENSSL_RUN_COMMAND nmake)
    endif()

    list(APPEND OPENSSL_CONFIG_FLAGS
        ${QUIC_OPENSSL_WIN_ARCH} ${OPENSSL_EXTRA_CONFIGURE_ARGS})

    if (QUIC_UWP_BUILD)
        list(APPEND OPENSSL_CONFIG_FLAGS no-async)
    endif()

    # Create working and output directories as needed
    file(MAKE_DIRECTORY ${OPENSSL_DIR}/debug/include)
    file(MAKE_DIRECTORY ${OPENSSL_DIR}/release/include)
    file(MAKE_DIRECTORY ${QUIC_BUILD_DIR}/${QUIC_OPENSSL}/quictls/debug)
    file(MAKE_DIRECTORY ${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/release)

    # Configure steps for debug and release variants
    add_custom_command(
        WORKING_DIRECTORY $<IF:$<CONFIG:Debug>,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/debug,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/release>
        OUTPUT $<IF:$<CONFIG:Debug>,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/debug/makefile,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/release/makefile>
        COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure ${OPENSSL_CONFIG_FLAGS} $<$<CONFIG:Debug>:--debug> $<$<CONFIG:Debug>:--prefix=${OPENSSL_DIR}/debug> $<$<NOT:$<CONFIG:Debug>>:--prefix=${OPENSSL_DIR}/release>

        COMMENT "OpenSSL configure"
    )

    # Compile/install commands for debug and release variants
    add_custom_command(
        OUTPUT $<IF:$<CONFIG:Debug>,${LIBSSL_DEBUG_PATH},${LIBSSL_PATH}>
        OUTPUT $<IF:$<CONFIG:Debug>,${LIBCRYPTO_DEBUG_PATH},${LIBCRYPTO_PATH}>
        DEPENDS $<IF:$<CONFIG:Debug>,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/debug/makefile,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/release/makefile>
        WORKING_DIRECTORY $<IF:$<CONFIG:Debug>,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/debug,${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/release>
        COMMAND ${OPENSSL_RUN_COMMAND} install_dev
        COMMENT "OpenSSL build"
    )

    # Named target depending on the final lib artifacts produced by custom commands
    add_custom_target(
        OpenSSL_Target
        DEPENDS
        $<$<CONFIG:Debug>:${LIBSSL_DEBUG_PATH}>
        $<$<NOT:$<CONFIG:Debug>>:${LIBSSL_PATH}>
        $<$<CONFIG:Debug>:${LIBCRYPTO_DEBUG_PATH}>
        $<$<NOT:$<CONFIG:Debug>>:${LIBCRYPTO_PATH}>
    )
    set_property(TARGET OpenSSL_Target PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}helpers")

    # Target to export to parent project
    add_library(OpenSSLQuic INTERFACE)
    add_dependencies(OpenSSLQuic
        OpenSSL_Target)
    target_include_directories(
        OpenSSLQuic
        INTERFACE
        $<BUILD_INTERFACE:$<$<CONFIG:Debug>:${OPENSSL_DIR}/debug/include>
        $<$<NOT:$<CONFIG:Debug>>:${OPENSSL_DIR}/release/include>>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_link_libraries(
        OpenSSLQuic
        INTERFACE
        $<$<CONFIG:Debug>:${LIBSSL_DEBUG_PATH}>
        $<$<CONFIG:Debug>:${LIBCRYPTO_DEBUG_PATH}>
        $<$<NOT:$<CONFIG:Debug>>:${LIBSSL_PATH}>
        $<$<NOT:$<CONFIG:Debug>>:${LIBCRYPTO_PATH}>
    )

    add_library(OpenSSLQuic::OpenSSLQuic ALIAS OpenSSLQuic)

else()

    set(LIBSSL_PATH ${OPENSSL_DIR}/lib/libssl${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(LIBCRYPTO_PATH ${OPENSSL_DIR}/lib/libcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})

    # Figure out the default cert directory
    execute_process(
        COMMAND openssl version -d
        RESULT_VARIABLE OPENSSL_VERSION_RESULT
        OUTPUT_VARIABLE FULL_OPENSSL_CERT_DIR)

    if (OPENSSL_VERSION_RESULT STREQUAL 0)
        # PARSE OPENSSLDIR
        string(REGEX MATCH "OPENSSLDIR:.*\"(.+)\"" OPENSSL_CERT_MATCH_VAR ${FULL_OPENSSL_CERT_DIR})
        if (CMAKE_MATCH_COUNT EQUAL 1)
            message(STATUS "Setting openssldir to ${CMAKE_MATCH_1}")
            list(APPEND OPENSSL_CONFIG_FLAGS --openssldir=\"${CMAKE_MATCH_1}\")
            set(CONFIGURED_OPENSSL_CERT_DIR TRUE)
        endif()
    endif()

    if (NOT CONFIGURED_OPENSSL_CERT_DIR)
        message(STATUS "Setting openssldir to default /usr/local/ssl")
        list(APPEND OPENSSL_CONFIG_FLAGS --openssldir=/usr/local/ssl)
    endif()

    list(APPEND OPENSSL_CONFIG_FLAGS --prefix=${OPENSSL_DIR})

    if (QUIC_ENABLE_SANITIZERS)
        list(APPEND OPENSSL_CONFIG_FLAGS enable-asan enable-ubsan)
    endif()
    if(ANDROID)
        message(STATUS "${ANDROID_ABI}")
        if(ANDROID_ABI STREQUAL "arm64-v8a")
            set(OPENSSL_BUILD_TYPE android-arm64)
        elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
            set(OPENSSL_BUILD_TYPE android-arm)
        elseif(ANDROID_ABI STREQUAL "x86")
            set(OPENSSL_BUILD_TYPE android-x86)
        elseif(ANDROID_ABI STREQUAL "x86_64")
            set(OPENSSL_BUILD_TYPE android-x86_64)
        else()
            message(FATAL_ERROR "Unknown android abi type")
        endif()
        set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure
            ${OPENSSL_BUILD_TYPE}
            -D__ANDROID_API__=29)
    elseif (CX_PLATFORM STREQUAL "linux")
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
            set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure
                linux-armv4 -DL_ENDIAN
                --cross-compile-prefix=${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-)
            list(APPEND OPENSSL_CONFIG_FLAGS -latomic)
        else()
            if (CMAKE_TARGET_ARCHITECTURE STREQUAL arm64)
                if (ONEBRANCH)
                    set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure linux-aarch64
                    --cross-compile-prefix=${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-)
                else()
                    set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure linux-aarch64)
                    check_c_compiler_flag(--target=aarch64-linux-gnu HAVE_AARCH64_TARGET)
                    if (HAVE_AARCH64_TARGET)
                        list(APPEND OPENSSL_CONFIG_FLAGS --target=aarch64-linux-gnu)
                    endif()
                endif()
                list(APPEND OPENSSL_CONFIG_FLAGS -latomic)
            elseif (CMAKE_TARGET_ARCHITECTURE STREQUAL arm)
                if (ONEBRANCH)
                    set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure linux-armv4
                    --cross-compile-prefix=${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-)
                else()
                    set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure linux-armv4)
                endif()
                list(APPEND OPENSSL_CONFIG_FLAGS -latomic)
            else()
                set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/config
                            CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER})
            endif()
        endif()
    elseif(CX_PLATFORM STREQUAL "darwin")
        # need to build with Apple's compiler
        if (CMAKE_OSX_ARCHITECTURES STREQUAL arm64)
            set(OPENSSL_CONFIG_CMD ARCHFLAGS="-arch arm64" ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure darwin64-arm64-cc)
        elseif(CMAKE_OSX_ARCHITECTURES STREQUAL x86_64)
            set(OPENSSL_CONFIG_CMD ARCHFLAGS="-arch x86_64" ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/Configure darwin64-x86_64-cc)
        else()
            message(ERROR "WTF ${CX_PLATFORM} ${CMAKE_TARGET_ARCHITECTURE}")
            set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/config)
        endif()
        list(APPEND OPENSSL_CONFIG_FLAGS -isysroot ${CMAKE_OSX_SYSROOT})
        if(SDK_NAME)
            list(APPEND OPENSSL_CONFIG_FLAGS "-m${SDK_NAME}-version-min=${DEPLOYMENT_TARGET}")
        elseif(CMAKE_OSX_DEPLOYMENT_TARGET)
            list(APPEND OPENSSL_CONFIG_FLAGS "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
        endif()
        if (ENABLE_BITCODE)
            list(APPEND OPENSSL_CONFIG_FLAGS -fembed-bitcode)
        endif()
    else()
        set(OPENSSL_CONFIG_CMD ${CMAKE_CURRENT_SOURCE_DIR}/${QUIC_OPENSSL}/config
            CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER})
    endif()

    # Create working and output directories as needed
    file(MAKE_DIRECTORY ${OPENSSL_DIR}/include)
    file(MAKE_DIRECTORY ${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL})

    # Configure steps for debug and release variants
    add_custom_command(
        WORKING_DIRECTORY ${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}
        OUTPUT ${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/Makefile
        COMMAND SYSTEM=${CMAKE_HOST_SYSTEM_NAME}
            ${OPENSSL_CONFIG_CMD} ${OPENSSL_CONFIG_FLAGS}
        COMMENT "OpenSSL configure"
    )

    include(ProcessorCount)
    ProcessorCount(NPROCS)

    message(STATUS "Configuring OpenSSL: ${OPENSSL_CONFIG_CMD} ${OPENSSL_CONFIG_FLAGS}")
    # Compile/install commands for debug and release variants
    add_custom_command(
        OUTPUT ${LIBSSL_PATH}
        OUTPUT ${LIBCRYPTO_PATH}
        DEPENDS ${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}/Makefile
        WORKING_DIRECTORY ${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}
        COMMAND make install_dev -j${NPROCS}
        COMMENT "OpenSSL build"
    )

    if (QUIC_USE_SYSTEM_LIBCRYPTO)
        # OpenSSL 3 uses different sources for static and dynamic libraries.
        # That is ok if you use either one consistently but it fails to link when we use dynamic crypto with static ssl.
        # To fix that we need little hackery - see quictls/ssl/build.info
        add_custom_command(
            OUTPUT ${LIBSSL_PATH}
            OUTPUT ${LIBCRYPTO_PATH}
            APPEND
            WORKING_DIRECTORY ${QUIC_BUILD_DIR}/submodules/${QUIC_OPENSSL}
            COMMAND ar x ${LIBCRYPTO_PATH} libcrypto-lib-packet.o libcommon-lib-tls_pad.o
            COMMAND ar r ${LIBSSL_PATH} libcrypto-lib-packet.o libcommon-lib-tls_pad.o
        )
    endif()

    # Named target depending on the final lib artifacts produced by custom commands
    add_custom_target(
        OpenSSL_Target
        DEPENDS
        ${LIBSSL_PATH}
        ${LIBCRYPTO_PATH}
    )
    set_property(TARGET OpenSSL_Target PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}helpers")

    # Target to export to parent project
    add_library(OpenSSLQuic INTERFACE)
    add_dependencies(OpenSSLQuic
        OpenSSL_Target)
    target_include_directories(
        OpenSSLQuic
        INTERFACE
        $<BUILD_INTERFACE:${OPENSSL_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    target_link_libraries(
        OpenSSLQuic
        INTERFACE
        ${LIBSSL_PATH}
    )

    if (QUIC_USE_SYSTEM_LIBCRYPTO)
        include(FindOpenSSL)
        if (OPENSSL_FOUND)
            # Get Major.Minor so 3.0 can match 3.0.2.
            # We cannot use VERSION_GREATER as 3.0 would work for 1.1.1 but they are not compatible.
            string(FIND ${OPENSSL_VERSION} "." VERSIONLEN REVERSE)
            string(SUBSTRING ${OPENSSL_VERSION} 0 ${VERSIONLEN}  OPENSSL_MAJORMINOR)
            string(FIND ${OPENSSL_VERSION} "." VERSIONLEN)
            string(SUBSTRING ${OPENSSL_VERSION} 0 ${VERSIONLEN}  OPENSSL_MAJOR)
            if (OPENSSL_VERSION VERSION_EQUAL EXPECTED_OPENSSL_VERSION OR OPENSSL_MAJORMINOR VERSION_EQUAL EXPECTED_OPENSSL_VERSION OR
                # 3.1 is compatible with 3.0, 3.2 and beyond maybe as well.
                (EXPECTED_OPENSSL_VERSION VERSION_EQUAL "3.0" AND OPENSSL_MAJOR EQUAL "3"))
                target_link_libraries(OpenSSLQuic INTERFACE OpenSSL::Crypto)
            else()
                message(FATAL_ERROR "OpenSSL ${EXPECTED_OPENSSL_VERSION} not found, found ${OPENSSL_VERSION}")
            endif()
        else()
            message(FATAL_ERROR "System OpenSSL not found when requested")
        endif()
    else()
        target_link_libraries(
            OpenSSLQuic
            INTERFACE
            ${LIBCRYPTO_PATH}
        )
    endif()

    add_library(OpenSSLQuic::OpenSSLQuic ALIAS OpenSSLQuic)

endif()
