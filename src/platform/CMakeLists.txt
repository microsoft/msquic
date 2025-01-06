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
    set(SOURCES ${SOURCES} platform_winuser.c storage_winuser.c datapath_win.c datapath_winuser.c datapath_xplat.c)
    if(QUIC_UWP_BUILD OR
       QUIC_GAMECORE_BUILD OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm" OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm64" OR
       ${SYSTEM_PROCESSOR} STREQUAL "arm64ec")
        set(SOURCES ${SOURCES} datapath_raw_dummy.c)
    else()
        set(SOURCES ${SOURCES} datapath_raw.c datapath_raw_win.c datapath_raw_socket.c datapath_raw_socket_win.c datapath_raw_xdp_win.c)
    endif()
else()
    set(SOURCES ${SOURCES} inline.c platform_posix.c storage_posix.c cgroup.c datapath_unix.c)
    if(CX_PLATFORM STREQUAL "linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(SOURCES ${SOURCES} datapath_linux.c datapath_epoll.c)
        if (QUIC_LINUX_XDP_ENABLED)
            set(SOURCES ${SOURCES} datapath_xplat.c datapath_raw.c datapath_raw_linux.c datapath_raw_socket.c datapath_raw_socket_linux.c datapath_raw_xdp_linux.c)
        else()
            set(SOURCES ${SOURCES} datapath_xplat.c datapath_raw_dummy.c)
        endif()
    else()
        set(SOURCES ${SOURCES} datapath_kqueue.c)
    endif()

    # Compile for Android failed by __atomic_add_fetch(), only emulator and some old ChromeBooks are X86, so the performance penalty may be acceptable, do not patch all the atomic usage for now
    # > error: misaligned atomic operation may incur significant performance penalty; the expected alignment (8 bytes) exceeds the actual alignment (4 bytes)
    if (ANDROID AND ANDROID_ABI STREQUAL "x86")
        add_compile_options(-Wno-atomic-alignment)
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

add_library(msquic_platform STATIC ${SOURCES})

if("${CX_PLATFORM}" STREQUAL "windows")
    target_link_libraries(
        msquic_platform
        PUBLIC
        wbemuuid)
    target_link_libraries(msquic_platform PUBLIC winmm)
elseif(QUIC_LINUX_XDP_ENABLED)
    find_library(NL_LIB nl-3)
    find_library(NL_ROUTE_LIB nl-route-3)
    find_library(XDP_LIB libxdp.so)
    find_library(BPF_LIB libbpf.so)
    target_include_directories(msquic_platform PRIVATE /usr/include/xdp)
    target_include_directories(msquic_platform PRIVATE /usr/include/bpf)
    set(XDP_PROG_INCLUDE_DIR "-I/usr/include/bpf")

    # building XDP program
    add_custom_command(
        OUTPUT ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o
        COMMAND clang -O2 -g -target bpf
        -c ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c
        -o ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o
        ${XDP_PROG_INCLUDE_DIR}
        -I/usr/include/x86_64-linux-gnu
        # -DDEBUG
        DEPENDS ${PROJECT_SOURCE_DIR}/src/platform/datapath_raw_xdp_linux_kern.c
    )
    add_custom_target(xdp_program DEPENDS ${QUIC_OUTPUT_DIR}/datapath_raw_xdp_kern.o)
    add_dependencies(msquic_platform xdp_program)

    if (NOT BUILD_SHARED_LIBS)
        find_library(ELF_LIB elf)   # for static
        find_library(Z_LIB z)       # for static
        find_library(ZSTD_LIB zstd) # for static
        string(REPLACE ".so" ".a" NL_LIB ${NL_LIB})
        string(REPLACE ".so" ".a" NL_ROUTE_LIB ${NL_ROUTE_LIB})
        string(REPLACE ".so" ".a" ELF_LIB ${ELF_LIB})
        string(REPLACE ".so" ".a" Z_LIB ${Z_LIB})
        string(REPLACE ".so" ".a" ZSTD_LIB ${ZSTD_LIB})
        string(REPLACE ".so" ".a" XDP_LIB ${XDP_LIB})
        string(REPLACE ".so" ".a" BPF_LIB ${BPF_LIB})
    endif()

    target_link_libraries(msquic_platform PUBLIC ${XDP_LIB} ${BPF_LIB} ${NL_LIB} ${NL_ROUTE_LIB} ${ELF_LIB} ${Z_LIB} ${ZSTD_LIB})
endif()

target_link_libraries(msquic_platform PUBLIC inc)
target_link_libraries(msquic_platform PRIVATE warnings main_binary_link_args)

set_property(TARGET msquic_platform PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

if ("${CX_PLATFORM}" STREQUAL "windows")
    target_include_directories(
        msquic_platform
        PRIVATE
        ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES}
        ${PROJECT_SOURCE_DIR}/submodules/xdp-for-windows/published/external)
elseif(QUIC_LINUX_XDP_ENABLED)
    include_directories(/usr/include/libnl3)
    target_include_directories(msquic_platform PRIVATE ${EXTRA_PLATFORM_INCLUDE_DIRECTORIES})
endif()

if (MSVC AND (QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "schannel") AND NOT QUIC_ENABLE_SANITIZERS)
    target_compile_options(msquic_platform PRIVATE /analyze)
endif()

if(QUIC_TLS STREQUAL "openssl" OR QUIC_TLS STREQUAL "openssl3")
    target_link_libraries(msquic_platform PUBLIC OpenSSL)
    if (CX_PLATFORM STREQUAL "darwin")
        target_link_libraries(msquic_platform PUBLIC "-framework CoreFoundation" "-framework Security")
    endif()
elseif(QUIC_TLS STREQUAL "schannel")
    target_link_libraries(msquic_platform PUBLIC secur32)
    if (NOT QUIC_GAMECORE_BUILD)
        target_link_libraries(msquic_platform PUBLIC onecore)
    endif()
endif()
