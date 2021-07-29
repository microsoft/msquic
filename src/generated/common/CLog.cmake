# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Creates a target to build all generated clog files of the input
# sources
#
function(CLOG_GENERATE_TARGET)
    set(library ${ARGV0})
    set(library_type ${ARGV1})
    list(REMOVE_AT ARGV 0)
    list(REMOVE_AT ARGV 0)
     # message(STATUS "****************<<<<<<<   CLOG(${library}))    >>>>>>>>>>>>>>>*******************")
     # message(STATUS ">>>> CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")
     # message(STATUS ">>>> CMAKE_CLOG_SIDECAR_DIRECTORY = ${CMAKE_CLOG_SIDECAR_DIRECTORY}")
     # message(STATUS ">>>> CMAKE_CLOG_CONFIG_PROFILE = ${CMAKE_CLOG_CONFIG_PROFILE}")
     # message(STATUS ">>>> CLOG Library = ${library}")
     # message(STATUS ">>>> CMAKE_CXX_COMPILER_ID = ${CMAKE_CXX_COMPILER_ID}")

    foreach(arg IN LISTS ARGV)
        get_filename_component(RAW_FILENAME ${arg} NAME)
        set(ARG_CLOG_FILE ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${library}/${RAW_FILENAME}.clog.h)
        set(ARG_CLOG_C_FILE ${CMAKE_CLOG_OUTPUT_DIRECTORY}/${library}/${library}_${RAW_FILENAME}.clog.h.c)

        # message(STATUS ">>>>>>> CLOG Source File = ${RAW_FILENAME}")

        set(ARG_CLOG_DYNAMIC_TRACEPOINT "")
        if (${library_type} STREQUAL "DYNAMIC")
            set(ARG_CLOG_DYNAMIC_TRACEPOINT "--dynamicTracepointProvider")
        endif()

        add_custom_command(
            OUTPUT ${ARG_CLOG_FILE} ${ARG_CLOG_C_FILE}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${arg}
            DEPENDS ${CMAKE_CLOG_CONFIG_FILE}
            DEPENDS ${CMAKE_CLOG_EXTRA_DEPENDENCIES}
            COMMENT "CLOG: clog --readOnly ${ARG_CLOG_DYNAMIC_TRACEPOINT} -p ${CMAKE_CLOG_CONFIG_PROFILE} --scopePrefix ${library} -c ${CMAKE_CLOG_CONFIG_FILE} -s ${CMAKE_CLOG_SIDECAR_DIRECTORY}/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}"
            COMMAND clog --readOnly ${ARG_CLOG_DYNAMIC_TRACEPOINT} -p ${CMAKE_CLOG_CONFIG_PROFILE} --scopePrefix ${library} -c ${CMAKE_CLOG_CONFIG_FILE} -s ${CMAKE_CLOG_SIDECAR_DIRECTORY}/clog.sidecar -i ${CMAKE_CURRENT_SOURCE_DIR}/${arg} -o ${ARG_CLOG_FILE}
        )

        set_property(SOURCE ${arg}
            APPEND PROPERTY OBJECT_DEPENDS ${ARG_CLOG_FILE}
        )

        list(APPEND clogfiles ${ARG_CLOG_C_FILE})
    endforeach()

    if (${library_type} STREQUAL "DYNAMIC")
        add_library(${library} STATIC ${clogfiles})

        add_library("${library}.provider" OBJECT ${clogfiles})
        target_compile_definitions("${library}.provider" PRIVATE BUILDING_TRACEPOINT_PROVIDER)
        set_property(TARGET "${library}.provider" PROPERTY POSITION_INDEPENDENT_CODE ON)

        target_include_directories("${library}.provider" PUBLIC $<BUILD_INTERFACE:${CLOG_INCLUDE_DIRECTORY}>)
        target_include_directories("${library}.provider" PUBLIC $<BUILD_INTERFACE:${CMAKE_CLOG_OUTPUT_DIRECTORY}/${library}>)
    else()
        add_library(${library} ${library_type} ${clogfiles})
        add_library("${library}.provider" INTERFACE)
    endif()

    target_link_libraries(${library} PUBLIC ${CMAKE_DL_LIBS})
    target_include_directories(${library} PUBLIC $<BUILD_INTERFACE:${CLOG_INCLUDE_DIRECTORY}>)
    target_include_directories(${library} PUBLIC $<BUILD_INTERFACE:${CMAKE_CLOG_OUTPUT_DIRECTORY}/${library}>)

    # message(STATUS "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
endfunction()
