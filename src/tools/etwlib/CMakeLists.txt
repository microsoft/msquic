# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES QuicEventCollection.cpp)

add_library(msquicetw STATIC ${SOURCES})

target_compile_options(msquicetw PRIVATE ${QUIC_WARNING_FLAGS} ${QUIC_CXX_FLAGS})
target_compile_definitions(msquicetw PRIVATE ${QUIC_COMMON_DEFINES})

target_include_directories(msquicetw PRIVATE ${QUIC_INCLUDE_DIR})

set_property(TARGET msquicetw PROPERTY FOLDER "tools")
