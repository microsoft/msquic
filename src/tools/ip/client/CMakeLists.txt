# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This does not use add_quic_tool because it doesn't use platform
add_executable(quicipclient quicipclient.cpp)

target_link_libraries(quicipclient msquic inc warnings)

target_include_directories(quicipclient PRIVATE ${PROJECT_SOURCE_DIR}/src/tools/ip)

set_property(TARGET quicipclient PROPERTY FOLDER "tools")
