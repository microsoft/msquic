# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicipclient quicipclient.cpp)

target_link_libraries(quicipclient msquic base warnings)

target_include_directories(quicipclient PRIVATE ${PROJECT_SOURCE_DIR}/src/tools/ip)

set_property(TARGET quicipclient PROPERTY FOLDER "tools")
