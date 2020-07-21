# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(spinquic spinquic.cpp)

target_link_libraries(spinquic msquic platform base)

set_property(TARGET spinquic PROPERTY FOLDER "tools")

if (NOT MSVC)
    target_compile_options(spinquic PRIVATE -Wno-missing-field-initializers)
endif()
