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
    set(LINUX_XDP_ENABLED FALSE)
    set(SOURCES ${SOURCES} inline.c platform_posix.c storage_posix.c cgroup.c)
    if(CX_PLATFORM STREQUAL "linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(SOURCES ${SOURCES} datapath_linux.c datapath_epoll.c)
        if((${UBUNTU_VERSION} STREQUAL "22.04") AND
           (${SYSTEM_PROCESSOR} STREQUAL "x86_64") AND
           (NOT ANDROID))
           set(LINUX_XDP_ENABLED TRUE)
           set(SOURCES ${SOURCES} datapath_raw_linux.c datapath_raw_socket.c datapath_raw_socket_linux.c datapath_raw_xdp_linux.c)
        else()
            set(SOURCES ${SOURCES} datapath_raw_dummy.c)
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
elseif(LINUX_XDP_ENABLED)
    # XDP Tools and libbpf paths
    set(XDP_TOOLS_DIR ${PROJECT_SOURCE_DIR}/submodules/xdp-tools)
    set(LIBXDP_DIR ${XDP_TOOLS_DIR}/lib/libxdp)
    set(LIBBPF_DIR ${XDP_TOOLS_DIR}/lib/libbpf/src)
    set(LIBXDP_PATH ${LIBXDP_DIR}/libxdp.so)
    set(LIBBPF_PATH ${LIBBPF_DIR}/libbpf.so)

    # Custom command to build XDP Tools
    add_custom_command(
        OUTPUT ${LIBXDP_PATH} ${LIBBPF_PATH} ${QUIC_OUTPUT_DIR}/xdp-dispatcher.o
        COMMAND ./configure
        COMMAND make
        # Experimental!
        # xdp-dispatcher.o need to be placed at
        # - "./" (libxdp Debug build)
        # - "/usr/lib/bpf"
        # - Specified by LIBXDP_OBJECT_PATH
        COMMAND cp ${XDP_TOOLS_DIR}/lib/libxdp/xdp-dispatcher.o ${QUIC_OUTPUT_DIR}/
        WORKING_DIRECTORY ${XDP_TOOLS_DIR}
    )

    # Add custom target and make platform depend on it
    add_custom_target(xdp_tools DEPENDS ${LIBXDP_PATH} ${LIBBPF_PATH})
    add_dependencies(platform xdp_tools)

    # Include directories for libxdp.so and libbpf.so
    target_include_directories(platform PRIVATE ${XDP_TOOLS_DIR}/headers/xdp)
    target_include_directories(platform PRIVATE ${XDP_TOOLS_DIR}/lib/libbpf/src)
    target_include_directories(platform PRIVATE ${XDP_TOOLS_DIR}/lib/libbpf/src/root/usr/include) # TODO: use installed path

    # building XDP program
    add_custom_command(
        OUTPUT ${PROJECT_SOURCE_DIR}/datapath_raw_xdp_kern.o
        OUTPUT ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o
        COMMAND clang -O2 -g -target bpf -c ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c -o ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o -I${PROJECT_SOURCE_DIR}/submodules/xdp-tools/lib -I/usr/include/x86_64-linux-gnu
        DEPENDS ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c
    )

    add_custom_target(xdp_prog ALL
        DEPENDS ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o)
    add_dependencies(platform xdp_prog)

    find_library(NL_LIB nl-3)
    find_library(NL_ROUTE_LIB nl-route-3)
    if (BUILD_SHARED_LIBS)
        add_custom_target(
            CopyLibsAndLinks ALL
            COMMAND cp -P ${LIBXDP_DIR}/*.so* ${QUIC_OUTPUT_DIR}/
            COMMAND cp -P ${LIBBPF_DIR}/*.so* ${QUIC_OUTPUT_DIR}/
            DEPENDS xdp_tools
        )
        set_target_properties(platform PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE)
        set_target_properties(platform PROPERTIES INSTALL_RPATH "${QUIC_OUTPUT_DIR}/libxdp.so;${QUIC_OUTPUT_DIR}/libbpf.so")
        add_dependencies(platform CopyLibsAndLinks)
        target_link_libraries(platform PUBLIC ${QUIC_OUTPUT_DIR}/libxdp.so ${QUIC_OUTPUT_DIR}/libbpf.so)
    else()
        find_library(ELF_LIB elf) # for static
        find_library(Z_LIB z)     # for static
        string(REPLACE ".so" ".a" NL_LIB ${NL_LIB})
        string(REPLACE ".so" ".a" NL_ROUTE_LIB ${NL_ROUTE_LIB})
        string(REPLACE ".so" ".a" ELF_LIB ${ELF_LIB})
        string(REPLACE ".so" ".a" Z_LIB ${Z_LIB})
        target_link_libraries(platform PUBLIC ${LIBXDP_DIR}/libxdp.a ${LIBBPF_DIR}/libbpf.a)
    endif()
    target_link_libraries(platform PUBLIC ${NL_LIB} ${NL_ROUTE_LIB} ${ELF_LIB} ${Z_LIB})
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
elseif(LINUX_XDP_ENABLED)
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
