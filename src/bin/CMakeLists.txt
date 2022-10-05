# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if(WIN32)
    configure_file(winuser/msquic.rc.in ${CMAKE_CURRENT_BINARY_DIR}/msquic.rc )
    configure_file(winuser/msquic.def.in ${CMAKE_CURRENT_BINARY_DIR}/msquic.def )
    set(SOURCES winuser/dllmain.c ${CMAKE_CURRENT_BINARY_DIR}/msquic.rc $<TARGET_OBJECTS:MsQuicEtw_Resource>)
else()
    set(SOURCES linux/init.c)
endif()

if(BUILD_SHARED_LIBS)
    add_library(msquic SHARED ${SOURCES})
    target_link_libraries(msquic PRIVATE core platform inc warnings logging base_link main_binary_link_args)
    set_target_properties(msquic PROPERTIES OUTPUT_NAME ${QUIC_LIBRARY_NAME})
    if (NOT WIN32)
        set_target_properties(msquic PROPERTIES SOVERSION ${QUIC_MAJOR_VERSION} VERSION ${QUIC_FULL_VERSION})
    endif()
else()
    add_library(msquic_static STATIC static/empty.c)
    target_link_libraries(msquic_static PRIVATE core platform inc logging main_binary_link_args)
    target_compile_definitions(msquic_static PUBLIC QUIC_BUILD_STATIC)
    set_property(TARGET msquic_static PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

    # We need to take given library and walk all its dependencies, including
    # transient dependencies. For each dependency, if it either compiles
    # directly to or imports a static library, that library needs to be
    # added to the QUIC_STATIC_LIBS list. This list is ultimately fed into
    # the archiving utility to produce a monolithic static library as
    # static library flags.
    #
    # Here, we exclude the inc interface target which includes various system
    # libraries we do not wish to archive for distribution.
    set(EXCLUDE_LIST "inc")
    if (CX_PLATFORM STREQUAL "darwin")
        list(APPEND EXCLUDE_LIST "-framework CoreFoundation" "-framework Security")
    endif()
    set_property(GLOBAL PROPERTY VISITED_TARGETS_PROP "${EXCLUDE_LIST}")
    set_property(GLOBAL PROPERTY QUIC_STATIC_LIBS "")
    function(flatten_link_dependencies CURRENT_TARGET)
        # Check first if we've already flattened the dependencies of this
        # library (possible if the dependency exists multiple times in the
        # same dependency graph)
        get_property(VISITED_TARGETS GLOBAL PROPERTY VISITED_TARGETS_PROP)

        if(${CURRENT_TARGET} IN_LIST VISITED_TARGETS)
            return()
        endif()

        # Ensure we don't process this target again
        list(APPEND VISITED_TARGETS ${CURRENT_TARGET})
        set_property(GLOBAL PROPERTY VISITED_TARGETS_PROP ${VISITED_TARGETS})

        # Uncomment to understand the dependency walk
        # message(STATUS "Evaluating linker output and dependencies for ${CURRENT_TARGET}")

        if(NOT TARGET ${CURRENT_TARGET})
            string(FIND ${CURRENT_TARGET} "$<LINK_ONLY:" LINK_ONLY)
            string(FIND ${CURRENT_TARGET} "Threads::Threads" THREADS_TARGET)
            string(FIND ${CURRENT_TARGET} "${CMAKE_STATIC_LIBRARY_SUFFIX}" SUFFIX_INDEX)
            if(${SUFFIX_INDEX} EQUAL "-1")
                string(APPEND CURRENT_TARGET "${CMAKE_STATIC_LIBRARY_SUFFIX}")
            endif()

            if(${LINK_ONLY} EQUAL "-1" AND ${THREADS_TARGET} EQUAL "-1")
                # This is expected to be a generator expression that maps
                # to a static library
                set_property(
                    GLOBAL
                    APPEND
                    PROPERTY QUIC_STATIC_LIBS
                    \"${CURRENT_TARGET}\"
                )
            endif()
            return()
        endif()

        # Check if this is an interface target
        get_target_property(TARGET_TYPE ${CURRENT_TARGET} TYPE)

        get_target_property(TARGET_OUTPUT ${CURRENT_TARGET} OUTPUT_NAME)
        if(NOT TARGET_OUTPUT)
            # The target's logical name is used as the base name if the
            # output name property isn't specified
            set(TARGET_OUTPUT ${CURRENT_TARGET})
        endif()

        if(${TARGET_TYPE} STREQUAL "STATIC_LIBRARY")
            get_target_property(OUTPUT_DIR ${CURRENT_TARGET} ARCHIVE_OUTPUT_DIRECTORY)
            if(OUTPUT_DIR)
                set(STATIC_LIB "${OUTPUT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}${TARGET_OUTPUT}${CMAKE_STATIC_LIBRARY_SUFFIX}")
                set_property(
                    GLOBAL
                    APPEND
                    PROPERTY QUIC_STATIC_LIBS
                    \"${STATIC_LIB}\"
                )
            endif()
        endif()

        # Next, recursively invoke this function for each dependency

        get_target_property(LINK_LIBS ${CURRENT_TARGET} LINK_LIBRARIES)
        get_target_property(INTERFACE_LIBS ${CURRENT_TARGET} INTERFACE_LINK_LIBRARIES)
        get_target_property(DEPS ${CURRENT_TARGET} LINK_DEPENDS)

        if(LINK_LIBS)
            foreach(DEP ${LINK_LIBS})
                flatten_link_dependencies(${DEP})
            endforeach()
        endif()

        if(INTERFACE_LIBS)
            foreach(DEP ${INTERFACE_LIBS})
                flatten_link_dependencies(${DEP})
            endforeach()
        endif()
    endfunction()

    flatten_link_dependencies(msquic_static)

    get_property(DEPS_LIST GLOBAL PROPERTY QUIC_STATIC_LIBS)
    set(DEPS_STRING "")
    foreach(line ${DEPS_LIST})
        set(DEPS_STRING "${DEPS_STRING}${line} ")
    endforeach(line)

    # Uncomment to analyze which dependencies were traversed
    # message(STATUS "DEPS: ${DEPS_LIST}, ${QUIC_BUILD_DIR}")

    if(APPLE)
        # Emit all linker inputs at build time to resolve generator expressions
        set(QUIC_DEPS_FILE ${CMAKE_CURRENT_BINARY_DIR}/$<IF:$<CONFIG:Debug>,Debug,Release>/quicdeps.txt)
        file(
            GENERATE
            OUTPUT ${QUIC_DEPS_FILE}
            CONTENT "${DEPS_STRING}"
        )

        # Run archiver tool
        add_custom_command(
            OUTPUT ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
            COMMAND libtool -static -o \"${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}\" @${QUIC_DEPS_FILE}
            DEPENDS ${QUIC_DEPS_FILE}
            DEPENDS core
            DEPENDS platform
            DEPENDS msquic_static
        )
    elseif(WIN32)
        set(NODEFAULTS "")
        foreach(EXCLUDE ${EXCLUDE_LIST})
            string(APPEND NODEFAULTS "/NODEFAULTLIB:${EXCLUDE}${CMAKE_STATIC_LIBRARY_SUFFIX} ")
        endforeach()

        # Exclude libraries for the corresponding msvcrts
        # https://docs.microsoft.com/en-us/cpp/error-messages/tool-errors/linker-tools-warning-lnk4098?view=msvc-160
        string(APPEND NODEFAULTS "/NODEFAULTLIB:msvcrt.lib /NODEFAULTLIB:msvcrtd.lib /NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
        # Uncomment to inspect which libraries will have referenced symbols ignored
        # message(STATUS "NODEFAULTS: ${NODEFAULTS}")

        # Emit all linker inputs at build time to resolve generator expressions
        set(QUIC_DEPS_FILE ${CMAKE_CURRENT_BINARY_DIR}/$<IF:$<CONFIG:Debug>,Debug,Release>/quicdeps.txt)
        file(
            GENERATE
            OUTPUT ${QUIC_DEPS_FILE}
            CONTENT "/OUT:\"${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}\" ${DEPS_STRING} ${NODEFAULTS}"
        )

        # Run archiver tool (lib.exe) on our generated linker args
        add_custom_command(
            OUTPUT ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
            COMMAND ${CMAKE_AR} @${QUIC_DEPS_FILE}
            COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}" "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}"
            DEPENDS ${QUIC_DEPS_FILE}
            DEPENDS core
            DEPENDS platform
            DEPENDS msquic_static
        )
    else()
        # Emit all linker inputs at build time to resolve generator expressions
        set(QUIC_DEPS_FILE ${CMAKE_CURRENT_BINARY_DIR}/$<IF:$<CONFIG:Debug>,Debug,Release>/quicdeps.txt)
        set(DEPS_LINES "")
        foreach(line ${DEPS_LIST})
            # message(STATUS ${line})
            set(DEPS_LINES "${DEPS_LINES}addlib ${line}\n")
        endforeach(line)
        file(
            GENERATE
            OUTPUT ${QUIC_DEPS_FILE}
            CONTENT "create \"${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}\"\n${DEPS_LINES}save\nend\n"
        )

        # Run archiver tool
        add_custom_command(
            OUTPUT ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
            COMMAND ${CMAKE_AR} -M < ${QUIC_DEPS_FILE}
            DEPENDS ${QUIC_DEPS_FILE}
            DEPENDS core
            DEPENDS platform
            DEPENDS msquic_static
        )
    endif()

    add_custom_target(
        msquic_lib
        DEPENDS
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}
    )

    set_property(TARGET msquic_lib PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

    message(STATUS "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}")

    # Provide interface library to link the monolithic library
    # NOTE: It is important that this interface library NOT link directly to
    # msquic_static or the linker flags will inadvertently bring in symbols
    # that are already linked as part of the static library. Users can link to
    # msquic_static directly if they don't need the monolithic library.
    add_library(msquic INTERFACE)
    target_compile_definitions(msquic INTERFACE QUIC_BUILD_STATIC)
    target_link_libraries(msquic
        INTERFACE
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${CMAKE_STATIC_LIBRARY_PREFIX}${QUIC_LIBRARY_NAME}${CMAKE_STATIC_LIBRARY_SUFFIX}
    )
    if (CX_PLATFORM STREQUAL "darwin")
        target_link_libraries(msquic INTERFACE "-framework CoreFoundation" "-framework Security")
    endif()
    add_dependencies(msquic msquic_lib)
endif()

set_property(TARGET msquic PROPERTY FOLDER "${QUIC_FOLDER_PREFIX}libraries")

if(WIN32)
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_BINARY_DIR}/msquic.def\"")
elseif (CX_PLATFORM STREQUAL "linux")
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "-Wl,--version-script=\"${CMAKE_CURRENT_SOURCE_DIR}/linux/exports.txt\"")
elseif (CX_PLATFORM STREQUAL "darwin")
    SET_TARGET_PROPERTIES(msquic
        PROPERTIES LINK_FLAGS "-exported_symbols_list \"${CMAKE_CURRENT_SOURCE_DIR}/darwin/exports.txt\"")
endif()

if(BUILD_SHARED_LIBS)
    target_include_directories(msquic PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../inc>
        $<INSTALL_INTERFACE:${include_dest}>)
else()
    target_include_directories(msquic_static INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../inc>
        $<INSTALL_INTERFACE:${include_dest}>)
    target_include_directories(msquic INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../inc>
        $<INSTALL_INTERFACE:${include_dest}>)
endif()

set(PUBLIC_HEADERS
    ../inc/msquic.h
    ../inc/msquic_winuser.h
    ../inc/msquic_posix.h
    ../inc/quic_sal_stub.h)

install(TARGETS msquic EXPORT msquic DESTINATION lib)
install(FILES ${PUBLIC_HEADERS} DESTINATION include)

configure_file(msquic-config.cmake.in ${CMAKE_BINARY_DIR}/msquic-config.cmake)

install(FILES ${CMAKE_BINARY_DIR}/msquic-config.cmake DESTINATION share/msquic)

if(BUILD_SHARED_LIBS)
    install(EXPORT msquic DESTINATION share/msquic)
endif()

if (MSVC AND NOT QUIC_ENABLE_SANITIZERS AND BUILD_SHARED_LIBS)
    target_compile_options(msquic PRIVATE /analyze)
endif()
