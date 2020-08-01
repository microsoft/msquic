# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES QuicUPnP.cpp)

add_library(quicupnp STATIC ${SOURCES})

target_link_libraries(quicupnp PRIVATE inc)

set_property(TARGET quicupnp PROPERTY FOLDER "tools")
