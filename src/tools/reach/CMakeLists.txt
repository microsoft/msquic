# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicreach reach.cpp)

target_compile_options(quicreach PRIVATE ${QUIC_CXX_FLAGS})

set_property(TARGET quicreach PROPERTY FOLDER "tools")

target_link_libraries(quicreach msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicreach
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
