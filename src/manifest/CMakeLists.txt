# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Include Files that need CLOG processing
include("${CLOG_INCLUDE_DIRECTORY}/CLog.make")
include_directories(${CMAKE_CLOG_OUTPUT_DIRECTORY})


# Generate the MsQuicEtw header file.
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/bld/inc)
file(WRITE ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.rc)
    
add_custom_command(
    DEPENDS CLOG_GENERATED_FILES
    DEPENDS ${CMAKE_SOURCE_DIR}/manifest/MsQuicEtw.man
    OUTPUT ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.h
    OUTPUT ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.rc
    COMMAND mc.exe -um -h ${CMAKE_SOURCE_DIR}/bld/inc -r ${CMAKE_SOURCE_DIR}/bld/inc ${CMAKE_SOURCE_DIR}/src/manifest/MsQuicEtw.man)

add_custom_target(MsQuicEtw
    DEPENDS ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.h
    DEPENDS ${CMAKE_SOURCE_DIR}/bld/inc/MsQuicEtw.rc)
