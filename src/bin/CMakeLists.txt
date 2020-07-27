# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(SOURCES winuser/dllmain.c winuser/msquic.rc ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)
else()
    set(SOURCES linux/init.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${QUIC_C_FLAGS}")

add_library(msquic SHARED ${SOURCES})

set_property(TARGET msquic PROPERTY FOLDER "libraries")

target_compile_options(msquic PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        ${CLANG_GCC_WARNING_FLAGS}>
     $<$<CXX_COMPILER_ID:MSVC>:
        ${MSVC_WARNING_FLAGS}>)

target_link_libraries(msquic PRIVATE core platform)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
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

if(WIN32)
    target_link_libraries(msquic PRIVATE PLATFORM_CLOG_LIB CORE_CLOG_LIB)
else()
    add_library(msquictraceprovicer SHARED $<TARGET_OBJECTS:PLATFORM_CLOG_LIB> $<TARGET_OBJECTS:CORE_CLOG_LIB>)
    target_link_libraries(msquictraceprovicer PRIVATE ${LTTNGUST_LIBRARIES})
    target_link_libraries(msquic PRIVATE msquictraceprovicer)
    install(TARGETS msquictraceprovicer EXPORT msquictraceprovicer DESTINATION "${main_lib_dest}")
    install(EXPORT msquictraceprovicer DESTINATION ${msquic_dest})
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

if (WIN32)
    configure_file(msquic-config.cmake.in ${CMAKE_BINARY_DIR}/msquic-config.cmake )
else()
    configure_file(msquic-config-linux.cmake.in ${CMAKE_BINARY_DIR}/msquic-config.cmake)
endif()

install(FILES ${CMAKE_BINARY_DIR}/msquic-config.cmake DESTINATION ${msquic_dest})

install(EXPORT msquic DESTINATION ${msquic_dest})
