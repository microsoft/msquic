# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES QuicEventCollection.cpp)

add_library(msquicetw STATIC ${SOURCES})

target_compile_options(msquicetw PRIVATE ${QUIC_CXX_FLAGS})

set_property(TARGET msquicetw PROPERTY FOLDER "tools")
