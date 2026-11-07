# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(quicforward_send_test ForwarderSendTest.cpp)
target_include_directories(quicforward_send_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(quicforward_send_test PRIVATE inc warnings)
set_property(TARGET quicforward_send_test PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tools/forwarder")
add_test(NAME quicforward_send_test COMMAND quicforward_send_test)
