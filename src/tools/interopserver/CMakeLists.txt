# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    InteropServer.cpp
)

add_executable(quicinteropserver ${SOURCES})

set_property(TARGET quicinteropserver PROPERTY FOLDER "tools")

target_link_libraries(quicinteropserver msquic platform)

if (NOT MSVC)
    target_compile_options(quicinteropserver PRIVATE
        -Wno-missing-field-initializers
        -Wno-switch
        -Wno-write-strings)
endif()
