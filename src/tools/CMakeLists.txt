# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function(add_quic_tool)
    set(targetname ${ARGV0})
    list(REMOVE_AT ARGV 0)

    add_executable(${targetname} ${ARGV})
    target_link_libraries(${targetname} inc warnings msquic)

    if (BUILD_SHARED_LIBS)
        target_link_libraries(${targetname} platform)
    endif()

    target_link_libraries(${targetname} logging base_link)

    set_property(TARGET ${targetname} PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}tools")
endfunction()

function(quic_tool_warnings)
    target_link_libraries(${ARGV0} warnings)
endfunction()

add_subdirectory(attack)
add_subdirectory(interop)
add_subdirectory(interopserver)
add_subdirectory(ip/client)
add_subdirectory(ip/server)
add_subdirectory(lb)
add_subdirectory(load)
add_subdirectory(pcp)
add_subdirectory(post)
add_subdirectory(sample)
add_subdirectory(spin)
if(WIN32 AND (NOT QUIC_UWP_BUILD AND NOT QUIC_GAMECORE_BUILD))
    add_subdirectory(etw)
endif()
