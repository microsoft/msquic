# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicreach reach.cpp)

set_property(TARGET quicreach PROPERTY FOLDER "tools")

target_link_libraries(quicreach msquic platform)

if (NOT MSVC)
    target_compile_options(quicreach PRIVATE -Wno-missing-field-initializers)
endif()
