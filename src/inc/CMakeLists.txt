# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Base target for all other targets. Ensures all arguments required are correctly set

add_library(inc INTERFACE)

target_compile_options(inc INTERFACE ${QUIC_C_FLAGS})
target_compile_options(inc INTERFACE $<$<COMPILE_LANGUAGE:CXX>:${QUIC_CXX_FLAGS}>)

target_compile_definitions(inc INTERFACE ${QUIC_COMMON_DEFINES})
target_include_directories(inc INTERFACE ${QUIC_INCLUDE_DIR})

target_compile_features(inc INTERFACE cxx_std_17)
target_compile_features(inc INTERFACE c_std_11)

add_library(base_link INTERFACE)

if (HAS_GUARDCF)
    target_link_options(base_link INTERFACE /guard:cf /DYNAMICBASE)
endif()

if (NOT MSVC AND QUIC_ENABLE_SANITIZERS)
    target_link_libraries(base_link INTERFACE -fsanitize=address,leak,undefined,alignment)
endif()

if (NOT MSVC AND NOT APPLE AND NOT ANDROID)
    find_library(ATOMIC NAMES atomic libatomic.so.1)
    if (ATOMIC)
        message(STATUS "Found libatomic: ${ATOMIC}")
    else()
        message(STATUS "libatomic not found. If build fails, install libatomic")
    endif()
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(base_link INTERFACE Threads::Threads ${CMAKE_DL_LIBS})

if (ATOMIC)
    target_link_libraries(base_link INTERFACE ${ATOMIC})
endif()

if(WIN32)
    if(QUIC_UWP_BUILD)
        target_link_libraries(base_link INTERFACE OneCore ws2_32 ntdll)
    elseif(QUIC_GAMECORE_BUILD)
        target_link_options(inc INTERFACE ${Console_LinkOptions})
        target_compile_options(inc INTERFACE ${Console_ArchOptions})
        target_link_directories(inc INTERFACE ${Console_EndpointLibRoot})
        target_link_libraries(base_link INTERFACE xgameplatform ntdll advapi32)
    else()
        target_link_libraries(base_link INTERFACE ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
    endif()
    if (_MSVC_CXX_ARCHITECTURE_FAMILY STREQUAL "ARM64EC")
        target_link_libraries(base_link INTERFACE softintrin)
    endif()
endif()

add_library(warnings INTERFACE)
target_compile_options(warnings INTERFACE ${QUIC_WARNING_FLAGS})

add_library(main_binary_link_args INTERFACE)
if (WIN32 AND NOT BUILD_SHARED_LIBS)
    target_compile_options(main_binary_link_args INTERFACE /Zl)
endif()
