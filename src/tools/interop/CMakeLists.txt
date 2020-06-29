# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicinterop interop.cpp)

target_compile_options(quicinterop PRIVATE ${QUIC_CXX_FLAGS})

set_property(TARGET quicinterop PROPERTY FOLDER "tools")

target_link_libraries(quicinterop msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicinterop
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
