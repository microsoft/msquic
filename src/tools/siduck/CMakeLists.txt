# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicsiduck siduck.cpp)

set_property(TARGET quicsiduck PROPERTY FOLDER "tools")

target_link_libraries(quicsiduck msquic platform base)

if (NOT MSVC)
    target_compile_options(quicsiduck PRIVATE -Wno-unused-variable)
endif()
