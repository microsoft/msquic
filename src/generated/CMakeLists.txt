# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if (QUIC_CODE_CHECK)
    # enable static analyzers for this directory
    set(CMAKE_C_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY_AVAILABLE})
    set(CMAKE_C_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
    set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK_AVAILABLE})
endif()

add_library(logging_inc INTERFACE)
target_link_libraries(inc INTERFACE logging_inc)

if(QUIC_ENABLE_LOGGING)
    if(QUIC_LOGGING_TYPE STREQUAL "etw")
        target_link_libraries(inc INTERFACE MsQuicEtw_Header)
        add_library(logging INTERFACE)

    elseif(QUIC_LOGGING_TYPE STREQUAL "stdout")
        FILE(GLOB LOGGING_FILES ${CMAKE_CURRENT_SOURCE_DIR}/stdout/*.c)
        add_library(logging STATIC ${LOGGING_FILES})
        target_link_libraries(logging PRIVATE inc)

    elseif(QUIC_LOGGING_TYPE STREQUAL "lttng")
        # Generate CLOG tracing headers and sources for LTTng at cmake configure time.
        # The clog tool reads the sidecar and generates per-source-file headers/sources.
        set(CLOG_OUTPUT_DIR ${CMAKE_BINARY_DIR}/clog_output)
        set(CLOG_SIDECAR ${CMAKE_SOURCE_DIR}/src/manifest/clog.sidecar)
        set(CLOG_CONFIG_FILE ${CMAKE_SOURCE_DIR}/src/manifest/msquic.clog_config)
        set(CLOG_SCOPE_PREFIX "quic.clog")

        # Read the list of input files (relative paths from scripts/ directory)
        file(STRINGS ${CMAKE_SOURCE_DIR}/scripts/clog.inputs CLOG_RAW_INPUTS)
        set(CLOG_INPUT_FILES "")
        foreach(raw_input ${CLOG_RAW_INPUTS})
            get_filename_component(abs_input "${CMAKE_SOURCE_DIR}/scripts/${raw_input}" ABSOLUTE)
            list(APPEND CLOG_INPUT_FILES "${abs_input}")
        endforeach()

        # Create the output directory
        file(MAKE_DIRECTORY ${CLOG_OUTPUT_DIR})

        # Run clog to generate all LTTng tracing headers and source files
        message(STATUS "Generating CLOG tracing files for LTTng...")
        execute_process(
            COMMAND ${CMAKE_COMMAND} -E env DOTNET_ROLL_FORWARD=Major
                ${CLOG_EXECUTABLE}
                --readOnly
                -p linux
                --dynamicTracepointProvider
                --scopePrefix ${CLOG_SCOPE_PREFIX}
                -c ${CLOG_CONFIG_FILE}
                -s ${CLOG_SIDECAR}
                --outputDirectory ${CLOG_OUTPUT_DIR}
                --inputFiles ${CLOG_INPUT_FILES}
            RESULT_VARIABLE CLOG_RESULT
            OUTPUT_VARIABLE CLOG_OUTPUT
            ERROR_VARIABLE CLOG_ERROR
        )
        if (NOT CLOG_RESULT EQUAL 0)
            message(FATAL_ERROR "CLOG generation failed:\n${CLOG_ERROR}")
        endif()

        # Collect all generated C source files
        file(GLOB LOGGING_FILES ${CLOG_OUTPUT_DIR}/*.c)

        target_include_directories(logging_inc INTERFACE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
        target_include_directories(logging_inc INTERFACE
            $<BUILD_INTERFACE:${CLOG_OUTPUT_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
        target_include_directories(logging_inc INTERFACE
            $<BUILD_INTERFACE:${LTTNGUST_INCLUDE_DIRS}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

        add_library(logging STATIC ${LOGGING_FILES})
        target_link_libraries(logging PRIVATE inc)

        add_library(msquic.lttng SHARED ${LOGGING_FILES})
        target_compile_definitions(msquic.lttng PRIVATE BUILDING_TRACEPOINT_PROVIDER)
        target_link_libraries(msquic.lttng PRIVATE logging_inc inc)
        target_link_libraries(msquic.lttng PRIVATE ${LTTNGUST_LIBRARIES})
        set_target_properties(msquic.lttng PROPERTIES SOVERSION ${QUIC_FULL_VERSION} VERSION ${QUIC_FULL_VERSION})

        install(TARGETS msquic.lttng
            EXPORT msquic
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        )
    endif()

else()
    add_library(logging INTERFACE)
endif()
