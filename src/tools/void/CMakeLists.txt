# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicvoidserver server.cpp)

target_compile_options(quicvoidserver PRIVATE ${QUIC_CXX_FLAGS})

target_link_libraries(quicvoidserver msquic platform)

set_property(TARGET quicvoidserver PROPERTY FOLDER "tools")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicvoidserver
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
