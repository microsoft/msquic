# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(spinquic spinquic.cpp)

target_compile_options(spinquic PRIVATE ${QUIC_CXX_FLAGS})

target_link_libraries(spinquic msquic platform)

set_property(TARGET spinquic PROPERTY FOLDER "tools")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(spinquic
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
endif()
