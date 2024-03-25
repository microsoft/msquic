# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

set(SOURCES crypt.c hashtable.c pcp.c platform_worker.c toeplitz.c)

if("${CX_PLATFORM}" STREQUAL "windows")
    set(SOURCES ${SOURCES} platform_winuser.c storage_winuser.c datapath_win.c datapath_winuser.c)
    if(QUIC_UWP_BUILD OR
       QUIC_GAMECORE_BUILD OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm" OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm64" OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm64ec")
        set(SOURCES ${SOURCES} datapath_raw_dummy.c)
    else()
        set(SOURCES ${SOURCES} datapath_raw_win.c datapath_raw_socket.c datapath_raw_socket_win.c datapath_raw_xdp_win.c)
    endif()
else()
    set(SOURCES ${SOURCES} inline.c platform_posix.c storage_posix.c cgroup.c)
    if(CX_PLATFORM STREQUAL "linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(SOURCES ${SOURCES} datapath_linux.c datapath_epoll.c)
        if((${UBUNTU_VERSION} NOT STREQUAL "22.04") OR
           (${SYSTEM_PROCESSOR} STREQUAL "arm") OR
           (${SYSTEM_PROCESSOR} STREQUAL "arm64") OR
           (${SYSTEM_PROCESSOR} STREQUAL "arm64ec") OR
           (${SYSTEM_PROCESSOR} STREQUAL "aarch64") OR)
            set(SOURCES ${SOURCES} datapath_raw_dummy.c)
        else()
            set(SOURCES ${SOURCES} datapath_raw_linux.c datapath_raw_socket.c datapath_raw_socket_linux.c datapath_raw_xdp_linux.c)
        endif()
    else()
        set(SOURCES ${SOURCES} datapath_kqueue.c)
    endif()
endif()

if (QUIC_TLS STREQUAL "schannel")
    message(STATUS "Configuring for Schannel")
    set(SOURCES ${SOURCES} cert_capi.c crypt_bcrypt.c selfsign_capi.c tls_schannel.c)
elseif(QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "openssl3")
    message(STATUS "Configuring for OpenSSL")
    set(SOURCES ${SOURCES} tls_openssl.c crypt_openssl.c)
    if ("${CX_PLATFORM}" STREQUAL "windows")
        set(SOURCES ${SOURCES} certificates_capi.c cert_capi.c  selfsign_capi.c)
    elseif(CX_PLATFORM STREQUAL "linux")
        set(SOURCES ${SOURCES} certificates_posix.c selfsign_openssl.c)
    else()
        set(SOURCES ${SOURCES} certificates_darwin.c selfsign_openssl.c)
    endif()
else()
    message(FATAL_ERROR "TLS Provider not configured")
endif()


add_library(platform STATIC ${SOURCES})

if ("${CX_PLATFORM}" STREQUAL "windows")
    target_link_libraries(
        platform
        PUBLIC
        wbemuuid)
    target_link_libraries(platform PUBLIC winmm)
elseif((${CX_PLATFORM} STREQUAL "linux") AND
       (${UBUNTU_VERSION} STREQUAL "22.04"))
    # XDP Tools and libbpf paths
    set(XDP_TOOLS_DIR ${PROJECT_SOURCE_DIR}/submodules/xdp-tools)
    set(LIBXDP_PATH ${XDP_TOOLS_DIR}/lib/libxdp/libxdp.so)
    set(LIBBPF_PATH ${XDP_TOOLS_DIR}/lib/libbpf/src/libbpf.so)

    # Custom command to build XDP Tools
    add_custom_command(
        OUTPUT ${LIBXDP_PATH} ${LIBBPF_PATH}
        COMMAND ./configure
        COMMAND make
        WORKING_DIRECTORY ${XDP_TOOLS_DIR}
    )

    # Add custom target and make platform depend on it
    add_custom_target(xdp_tools DEPENDS ${LIBXDP_PATH} ${LIBBPF_PATH})
    add_dependencies(platform xdp_tools)

    # Link platform to libxdp.so and libbpf.so
    target_link_libraries(platform PUBLIC ${LIBXDP_PATH} ${LIBBPF_PATH})

    # Include directories for libxdp.so and libbpf.so
    target_include_directories(platform PRIVATE ${XDP_TOOLS_DIR}/headers/xdp)
    target_include_directories(platform PRIVATE ${XDP_TOOLS_DIR}/lib/libbpf/src)
    target_include_directories(platform PRIVATE ${XDP_TOOLS_DIR}/lib/libbpf/src/root/usr/include) # TODO: use installed path

    # XDP program setting
    add_custom_command(
        OUTPUT ${PROJECT_SOURCE_DIR}/datapath_raw_xdp_kern.o
        COMMAND clang -O2 -g -target bpf -c ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c -o ${PROJECT_SOURCE_DIR}/datapath_raw_xdp_kern.o -I${PROJECT_SOURCE_DIR}/submodules/xdp-tools/lib -I/usr/include/x86_64-linux-gnu
        DEPENDS ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c
    )

    add_custom_target(
        XDP_PROG ALL
        DEPENDS ${PROJECT_SOURCE_DIR}/datapath_raw_xdp_kern.o
    )

    add_dependencies(platform XDP_PROG)

    # Assuming ${XDP_TOOLS_LIB_DIR} is the directory where libxdp.so and libbpf.so are located
    set_target_properties(platform PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE)
    set_target_properties(platform PROPERTIES INSTALL_RPATH "${XDP_TOOLS_DIR}/lib/libxdp;${XDP_TOOLS_DIR}/lib/libbpf/src")

    find_library(NL_LIB nl-3)
    find_library(NL_ROUTE_LIB nl-route-3)
    target_link_libraries(platform PUBLIC ${NL_LIB} ${NL_ROUTE_LIB})
endif()

target_link_libraries(platform PUBLIC inc)
target_link_libraries(platform PRIVATE warnings main_binary_link_args)

set_property(TARGET platform PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

if ("${CX_PLATFORM}" STREQUAL "windows")
    target_include_directories(
        platform
        PRIVATE
        ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES}
        ${PROJECT_SOURCE_DIR}/submodules/xdp-for-windows/published/external)
elseif((${CX_PLATFORM} STREQUAL "linux") AND
       (${UBUNTU_VERSION} STREQUAL "22.04"))
    include_directories(/usr/include/libnl3)
    target_include_directories(platform PRIVATE ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES})
endif()

if (MSVC AND (QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "schannel") AND NOT QUIC_ENABLE_SANITIZERS)
    target_compile_options(platform PRIVATE /analyze)
endif()

if(QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "openssl3")
    target_link_libraries(platform PUBLIC OpenSSL)
    if (CX_PLATFORM STREQUAL "darwin")
        target_link_libraries(platform PUBLIC "-framework CoreFoundation" "-framework Security")
    endif()
elseif(QUIC_TLS STREQUAL "schannel")
    target_link_libraries(platform PUBLIC secur32 onecore)
endif()
