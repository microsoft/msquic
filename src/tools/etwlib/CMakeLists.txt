# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES QuicEventCollection.cpp)

add_library(msquicetw STATIC ${SOURCES})

target_link_libraries(msquicetw PRIVATE inc)

set_property(TARGET msquicetw PROPERTY FOLDER "tools")
