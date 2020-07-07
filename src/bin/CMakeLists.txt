# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(SOURCES winuser/dllmain.c winuser/msquic.rc ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)
else()
    set(SOURCES linux/init.c)
endif()

add_library(msquic SHARED ${SOURCES})

set_property(TARGET msquic PROPERTY FOLDER "libraries")

target_compile_options(msquic PRIVATE ${QUIC_WARNING_FLAGS} ${QUIC_COMMON_FLAGS})
target_compile_definitions(msquic PRIVATE ${QUIC_COMMON_DEFINES})

target_include_directories(msquic PRIVATE ${QUIC_INCLUDE_DIR})

target_link_libraries(msquic PRIVATE core platform PLATFORM_CLOG_LIB CORE_CLOG_LIB)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(msquic PUBLIC
        ws2_32 schannel ntdll bcrypt ncrypt crypt32 iphlpapi advapi32)
    if(QUIC_UWP_BUILD)
        target_link_libraries(msquic PUBLIC OneCoreUAP)
    endif()
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/winuser/msquic.def\"")
else()
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "-Wl,--version-script=\"${CMAKE_CURRENT_SOURCE_DIR}/linux/exports.txt\"")
endif()

target_include_directories(msquic PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../inc>
    $<INSTALL_INTERFACE:${include_dest}>)

set(PUBLIC_HEADERS
    ../inc/msquic.h
    ../inc/msquic_winuser.h
    ../inc/msquic_linux.h
    ../inc/quic_sal_stub.h)

install(TARGETS msquic EXPORT msquic DESTINATION "${main_lib_dest}")
install(FILES ${PUBLIC_HEADERS} DESTINATION "${include_dest}")

configure_file(msquic-config.cmake.in ${CMAKE_BINARY_DIR}/msquic-config.cmake )
install(FILES ${CMAKE_BINARY_DIR}/msquic-config.cmake DESTINATION ${msquic_dest})
install(EXPORT msquic DESTINATION ${msquic_dest})
