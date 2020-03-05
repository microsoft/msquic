# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES QuicEventCollection.cpp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${QUIC_CXX_FLAGS}")

add_library(msquicetw STATIC ${SOURCES})
