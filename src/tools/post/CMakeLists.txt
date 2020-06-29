# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    post.cpp
)

add_executable(quicpost ${SOURCES})

target_compile_options(quicpost PRIVATE ${QUIC_CXX_FLAGS})

set_property(TARGET quicpost PROPERTY FOLDER "tools")

target_link_libraries(quicpost msquic platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(quicpost
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
