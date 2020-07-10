# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicinterop interop.cpp)

set_property(TARGET quicinterop PROPERTY FOLDER "tools")

target_link_libraries(quicinterop msquic platform)

if (NOT MSVC)
    target_compile_options(quicinterop PRIVATE
        -Wno-missing-field-initializers
        -Wno-unused-variable
        -Wno-write-strings)
endif()
