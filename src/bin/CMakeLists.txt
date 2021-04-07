# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if(WIN32)
    set(SOURCES winuser/dllmain.c winuser/msquic.rc $<TARGET_OBJECTS:MsQuicEtw_Resource>)
else()
    set(SOURCES linux/init.c)
endif()

if(BUILD_SHARED_LIBS)
    add_library(msquic SHARED ${SOURCES})
else()
    add_library(msquic STATIC static/init.c)
    target_compile_definitions(msquic PUBLIC QUIC_BUILD_STATIC)
endif()

set_property(TARGET msquic PROPERTY FOLDER "libraries")

target_link_libraries(msquic PRIVATE core platform inc warnings)

if(WIN32)
    if(QUIC_UWP_BUILD)
        target_link_libraries(msquic PUBLIC OneCoreUAP)
    endif()
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/winuser/msquic.def\"")
elseif (CX_PLATFORM STREQUAL "linux")
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "-Wl,--version-script=\"${CMAKE_CURRENT_SOURCE_DIR}/linux/exports.txt\"")
elseif (CX_PLATFORM STREQUAL "darwin")
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "-exported_symbols_list \"${CMAKE_CURRENT_SOURCE_DIR}/darwin/exports.txt\"")
endif()

target_include_directories(msquic PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../inc>
    $<INSTALL_INTERFACE:${include_dest}>)

set(PUBLIC_HEADERS
    ../inc/msquic.h
    ../inc/msquic_winuser.h
    ../inc/msquic_posix.h
    ../inc/quic_sal_stub.h)

install(TARGETS msquic EXPORT msquic DESTINATION "${main_lib_dest}")
install(FILES ${PUBLIC_HEADERS} DESTINATION "${include_dest}")

configure_file(msquic-config.cmake.in ${CMAKE_BINARY_DIR}/msquic-config.cmake)

install(FILES ${CMAKE_BINARY_DIR}/msquic-config.cmake DESTINATION ${msquic_dest})

if(BUILD_SHARED_LIBS)
    install(EXPORT msquic DESTINATION ${msquic_dest})
endif()

if(WIN32)
    add_library(msquic.lttng INTERFACE)
elseif(QUIC_ENABLE_LOGGING)
    add_library(msquic.lttng $<TARGET_OBJECTS:platform.clog.provider> $<TARGET_OBJECTS:core.clog.provider>)
    target_link_libraries(msquic.lttng inc)
    install(TARGETS msquic.lttng DESTINATION "${main_lib_dest}")
endif()

if (MSVC)
    target_compile_options(msquic PRIVATE /analyze)
endif()
