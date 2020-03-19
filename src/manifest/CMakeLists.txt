# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include Files that need CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})


# Generate the MsQuicEtw header file.
file(MAKE_DIRECTORY ${QUIC_BUILD_DIR}/inc)
file(WRITE ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)
    
add_custom_command(
    DEPENDS CLOG_GENERATED_FILES
    DEPENDS ${CMAKE_SOURCE_DIR}/src/manifest/MsQuicEtw.man
    OUTPUT ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h
    OUTPUT ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc
    COMMAND mc.exe -um -h ${QUIC_BUILD_DIR}/inc -r ${QUIC_BUILD_DIR}/inc ${CMAKE_SOURCE_DIR}/src/manifest/MsQuicEtw.man)

add_custom_target(MsQuicEtw
    DEPENDS ${QUIC_BUILD_DIR}/inc/MsQuicEtw.h
    DEPENDS ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)
