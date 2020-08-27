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

if (NOT MSVC AND QUIC_ENABLE_SANITIZERS)
    target_link_libraries(inc INTERFACE -fsanitize=address,leak,undefined)
endif()

if(QUIC_ENABLE_LOGGING)
    if(WIN32)
        add_dependencies(inc INTERFACE MsQuicEtw)
    else()
        target_link_libraries(inc INTERFACE ${LTTNGUST_LIBRARIES})
    endif()
endif()

if (NOT MSVC AND NOT APPLE)
    find_library(ATOMIC NAMES atomic libatomic.so.1)
    if (ATOMIC)
        message(STATUS "Found libatomic: ${ATOMIC}")
    endif()
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(inc INTERFACE Threads::Threads ${CMAKE_DL_LIBS} ${ATOMIC})

if(WIN32)
    target_link_libraries(inc INTERFACE ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()

add_library(warnings INTERFACE)
target_compile_options(warnings INTERFACE ${QUIC_WARNING_FLAGS})
