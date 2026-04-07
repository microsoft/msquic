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

# Common clog settings used for both build-time generation and the update target
set(CLOG_SIDECAR ${CMAKE_SOURCE_DIR}/src/manifest/clog.sidecar)
set(CLOG_CONFIG_FILE ${CMAKE_SOURCE_DIR}/src/manifest/msquic.clog_config)
set(CLOG_SCOPE_PREFIX "quic.clog")

# Read the list of clog input files (relative paths from scripts/ directory)
file(STRINGS ${CMAKE_SOURCE_DIR}/scripts/clog.inputs CLOG_RAW_INPUTS)
set(CLOG_INPUT_FILES "")
foreach(raw_input ${CLOG_RAW_INPUTS})
    get_filename_component(abs_input "${CMAKE_SOURCE_DIR}/scripts/${raw_input}" ABSOLUTE)
    list(APPEND CLOG_INPUT_FILES "${abs_input}")
endforeach()

# Helper macro: run clog --readOnly at configure time for the given profile.
# Output goes to a profile-specific subdirectory under CMAKE_BINARY_DIR/clog_output/.
# For lttng, the generated files are compiled into the build; for other profiles they
# serve as sidecar validation and decoder ring generation only.
macro(clog_generate_at_configure_time PROFILE EXTRA_ARGS OUTPUT_DIR_VAR)
    set(${OUTPUT_DIR_VAR} ${CMAKE_BINARY_DIR}/clog_output/${PROFILE})
    file(MAKE_DIRECTORY ${${OUTPUT_DIR_VAR}})
    message(STATUS "Generating CLOG tracing files for profile '${PROFILE}'...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env DOTNET_ROLL_FORWARD=Major
            ${CLOG_EXECUTABLE}
            --readOnly
            ${EXTRA_ARGS}
            -p ${PROFILE}
            --scopePrefix ${CLOG_SCOPE_PREFIX}
            -c ${CLOG_CONFIG_FILE}
            -s ${CLOG_SIDECAR}
            --outputDirectory ${${OUTPUT_DIR_VAR}}
            --inputFiles ${CLOG_INPUT_FILES}
        RESULT_VARIABLE _CLOG_RESULT
        OUTPUT_VARIABLE _CLOG_OUTPUT
        ERROR_VARIABLE _CLOG_ERROR
    )
    if (NOT _CLOG_RESULT EQUAL 0)
        message(FATAL_ERROR "CLOG generation failed for profile '${PROFILE}':\n${_CLOG_ERROR}")
    endif()
endmacro()

if(QUIC_ENABLE_LOGGING)
    if(QUIC_LOGGING_TYPE STREQUAL "etw")
        target_link_libraries(inc INTERFACE MsQuicEtw_Header)
        add_library(logging INTERFACE)

        # Run clog for the windows profile: validates the sidecar and generates
        # per-file stubs and decoder ring files into the build directory.
        if (CLOG_EXECUTABLE)
            clog_generate_at_configure_time("windows" "" CLOG_WINDOWS_OUTPUT_DIR)
        endif()

    elseif(QUIC_LOGGING_TYPE STREQUAL "stdout")
        FILE(GLOB LOGGING_FILES ${CMAKE_CURRENT_SOURCE_DIR}/stdout/*.c)
        add_library(logging STATIC ${LOGGING_FILES})
        target_link_libraries(logging PRIVATE inc)

        # Run clog for the macos profile: validates the sidecar and generates
        # per-file stubs and decoder ring files into the build directory.
        if (CLOG_EXECUTABLE)
            clog_generate_at_configure_time("macos" "" CLOG_MACOS_OUTPUT_DIR)
        endif()

    elseif(QUIC_LOGGING_TYPE STREQUAL "lttng")
        # Run clog for the linux profile: generates LTTng tracing headers and
        # source files that are compiled directly into the logging library.
        clog_generate_at_configure_time("linux" "--dynamicTracepointProvider" CLOG_LINUX_OUTPUT_DIR)

        # Collect all generated C source files for compilation
        file(GLOB LOGGING_FILES ${CLOG_LINUX_OUTPUT_DIR}/*.c)

        target_include_directories(logging_inc INTERFACE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
        target_include_directories(logging_inc INTERFACE
            $<BUILD_INTERFACE:${CLOG_LINUX_OUTPUT_DIR}>
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

# Provide a cmake target to update the clog sidecar and regenerate all platform
# stubs and decoder rings. Run this after adding new trace calls to source files:
#   cmake --build <build_dir> --target update_clog_sidecar
if (CLOG_EXECUTABLE)
    set(CLOG_UPDATE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/clog_update)
    add_custom_target(update_clog_sidecar
        COMMAND ${CMAKE_COMMAND} -E env DOTNET_ROLL_FORWARD=Major
            ${CLOG_EXECUTABLE}
            -p windows --scopePrefix ${CLOG_SCOPE_PREFIX}
            -c ${CLOG_CONFIG_FILE} -s ${CLOG_SIDECAR}
            --outputDirectory ${CLOG_UPDATE_OUTPUT_DIR}/windows
            --inputFiles ${CLOG_INPUT_FILES}
        COMMAND ${CMAKE_COMMAND} -E env DOTNET_ROLL_FORWARD=Major
            ${CLOG_EXECUTABLE}
            -p windows_kernel --scopePrefix ${CLOG_SCOPE_PREFIX}
            -c ${CLOG_CONFIG_FILE} -s ${CLOG_SIDECAR}
            --outputDirectory ${CLOG_UPDATE_OUTPUT_DIR}/windows_kernel
            --inputFiles ${CLOG_INPUT_FILES}
        COMMAND ${CMAKE_COMMAND} -E env DOTNET_ROLL_FORWARD=Major
            ${CLOG_EXECUTABLE}
            -p stubs --scopePrefix ${CLOG_SCOPE_PREFIX}
            -c ${CLOG_CONFIG_FILE} -s ${CLOG_SIDECAR}
            --outputDirectory ${CLOG_UPDATE_OUTPUT_DIR}/stubs
            --inputFiles ${CLOG_INPUT_FILES}
        COMMAND ${CMAKE_COMMAND} -E env DOTNET_ROLL_FORWARD=Major
            ${CLOG_EXECUTABLE}
            -p linux --dynamicTracepointProvider --scopePrefix ${CLOG_SCOPE_PREFIX}
            -c ${CLOG_CONFIG_FILE} -s ${CLOG_SIDECAR}
            --outputDirectory ${CLOG_UPDATE_OUTPUT_DIR}/linux
            --inputFiles ${CLOG_INPUT_FILES}
        COMMAND ${CMAKE_COMMAND} -E env DOTNET_ROLL_FORWARD=Major
            ${CLOG_EXECUTABLE}
            -p macos --scopePrefix ${CLOG_SCOPE_PREFIX}
            -c ${CLOG_CONFIG_FILE} -s ${CLOG_SIDECAR}
            --outputDirectory ${CLOG_UPDATE_OUTPUT_DIR}/macos
            --inputFiles ${CLOG_INPUT_FILES}
        COMMENT "Updating CLOG sidecar for all profiles. Re-run cmake after this completes."
        VERBATIM
    )
endif()
