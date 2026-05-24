# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# PrefixOpenSSLArchives
#
# Produce namespace-prefixed copies of the bundled OpenSSL static archives so
# the resulting MsQuic binary can coexist in the same process with a different
# copy of OpenSSL (e.g. a system `libcrypto.so.3` pulled in by an unrelated
# transitive dependency) without colliding on global C symbols.
#
# Mechanism: extract every globally-defined external symbol from the input
# archives and use `objcopy --redefine-syms` to rewrite the symbol table so
# both definitions and undefined references carry a `${QUIC_OPENSSL_SYMBOL_PREFIX}`
# prefix. The rename is applied to:
#   - The bundled `libssl.a` and `libcrypto.a` (their *defined* symbols).
#   - Any consumer's static archive that references OpenSSL (the *undefined*
#     references inside, so they resolve against the prefixed archives at the
#     final link step). For MsQuic this is `libmsquic_platform.a`, handled in
#     `src/platform/CMakeLists.txt`.
#
# This is a Linux-only feature today. Honoring `${CMAKE_NM}` / `${CMAKE_OBJCOPY}`
# makes the rename step cross-compile-safe. macOS support would require
# `llvm-objcopy` >= 13 (untested); PE/COFF lacks a flat-namespace symbol table
# and would need a fundamentally different approach.
#
# Function:
#   prefix_openssl_archives(
#       PREFIX        <symbol_prefix>          # e.g. "msquic_"
#       INPUT_TARGET  <bundled-openssl-target> # INTERFACE target whose
#                                              # INTERFACE_LINK_LIBRARIES
#                                              # contains the .a paths
#       OUTPUT_TARGET <new-interface-target>   # name of the renamed target
#                                              # to create
#   )
#
# After the call:
#   - INTERFACE IMPORTED target `<OUTPUT_TARGET>` exists with include dirs
#     copied from `<INPUT_TARGET>` and link libs pointing at the renamed
#     archives.
#   - Cache variables:
#       `<OUTPUT_TARGET>_REDEFINE_SYMS`  absolute path to the syms file
#                                        (so a consumer's POST_BUILD step can
#                                        apply the same rename to its own
#                                        archive)
#       `<OUTPUT_TARGET>_PREFIX_SCRIPT`  absolute path to
#                                        `cmake/openssl-prefix-rename.sh`
#                                        (so consumers do not have to
#                                        re-resolve the script path)
#

# Capture this module's directory at parse time so the script-path lookup is
# independent of the parent build's `CMAKE_SOURCE_DIR` (which may not be
# msquic's own root when msquic is consumed via `add_subdirectory`).
set(_PREFIX_OPENSSL_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/openssl-prefix-rename.sh")

function(prefix_openssl_archives)
    set(options)
    set(oneValueArgs PREFIX INPUT_TARGET OUTPUT_TARGET)
    set(multiValueArgs)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_PREFIX OR NOT ARG_INPUT_TARGET OR NOT ARG_OUTPUT_TARGET)
        message(FATAL_ERROR "prefix_openssl_archives requires PREFIX, INPUT_TARGET, and OUTPUT_TARGET")
    endif()

    if(NOT TARGET ${ARG_INPUT_TARGET})
        message(FATAL_ERROR "prefix_openssl_archives: INPUT_TARGET '${ARG_INPUT_TARGET}' does not exist")
    endif()

    # Pull the original archive paths off the INPUT_TARGET INTERFACE properties.
    get_target_property(_openssl_libs ${ARG_INPUT_TARGET} INTERFACE_LINK_LIBRARIES)
    get_target_property(_openssl_inc  ${ARG_INPUT_TARGET} INTERFACE_INCLUDE_DIRECTORIES)

    set(_orig_libssl)
    set(_orig_libcrypto)
    foreach(_lib IN LISTS _openssl_libs)
        if(_lib MATCHES "libssl\\.a$")
            set(_orig_libssl "${_lib}")
        elseif(_lib MATCHES "libcrypto\\.a$")
            set(_orig_libcrypto "${_lib}")
        endif()
    endforeach()

    if(NOT _orig_libssl OR NOT _orig_libcrypto)
        message(FATAL_ERROR "prefix_openssl_archives: ${ARG_INPUT_TARGET} does not expose both libssl.a and libcrypto.a (got: ${_openssl_libs})")
    endif()

    set(_out_dir            "${CMAKE_BINARY_DIR}/openssl-prefixed/${ARG_PREFIX}")
    set(_syms_file          "${_out_dir}/redefine.syms")
    set(_renamed_libssl     "${_out_dir}/libssl.a")
    set(_renamed_libcrypto  "${_out_dir}/libcrypto.a")
    set(_script             "${_PREFIX_OPENSSL_SCRIPT}")

    file(MAKE_DIRECTORY "${_out_dir}")

    # Forward the cross-compile-aware nm/objcopy to the helper script. If
    # ${CMAKE_NM} / ${CMAKE_OBJCOPY} are unset, the script falls back to its
    # own defaults (plain `nm` / `objcopy`).
    set(_env_args)
    if(CMAKE_NM)
        list(APPEND _env_args "NM=${CMAKE_NM}")
    endif()
    if(CMAKE_OBJCOPY)
        list(APPEND _env_args "OBJCOPY=${CMAKE_OBJCOPY}")
    endif()

    add_custom_command(
        OUTPUT "${_syms_file}"
        DEPENDS "${_orig_libssl}" "${_orig_libcrypto}" "${_script}"
        COMMAND ${CMAKE_COMMAND} -E env ${_env_args}
                "${_script}" gen-syms "${ARG_PREFIX}" "${_syms_file}"
                "${_orig_libssl}" "${_orig_libcrypto}"
        COMMENT "Generating OpenSSL symbol prefix-map (prefix=${ARG_PREFIX})"
        VERBATIM
    )

    add_custom_command(
        OUTPUT "${_renamed_libssl}"
        DEPENDS "${_orig_libssl}" "${_syms_file}" "${_script}"
        COMMAND ${CMAKE_COMMAND} -E env ${_env_args}
                "${_script}" apply "${_syms_file}" "${_orig_libssl}" "${_renamed_libssl}"
        COMMENT "Prefix-renaming libssl.a (prefix=${ARG_PREFIX})"
        VERBATIM
    )

    add_custom_command(
        OUTPUT "${_renamed_libcrypto}"
        DEPENDS "${_orig_libcrypto}" "${_syms_file}" "${_script}"
        COMMAND ${CMAKE_COMMAND} -E env ${_env_args}
                "${_script}" apply "${_syms_file}" "${_orig_libcrypto}" "${_renamed_libcrypto}"
        COMMENT "Prefix-renaming libcrypto.a (prefix=${ARG_PREFIX})"
        VERBATIM
    )

    add_custom_target(
        ${ARG_OUTPUT_TARGET}_Build
        DEPENDS "${_renamed_libssl}" "${_renamed_libcrypto}" "${_syms_file}"
    )

    add_library(${ARG_OUTPUT_TARGET} INTERFACE IMPORTED GLOBAL)
    add_dependencies(${ARG_OUTPUT_TARGET} ${ARG_OUTPUT_TARGET}_Build)
    set_target_properties(
        ${ARG_OUTPUT_TARGET}
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${_openssl_inc}"
    )
    target_link_libraries(
        ${ARG_OUTPUT_TARGET}
        INTERFACE "${_renamed_libssl}" "${_renamed_libcrypto}"
    )

    set(${ARG_OUTPUT_TARGET}_REDEFINE_SYMS "${_syms_file}" CACHE INTERNAL
        "Path to the prefix-rename syms file used by ${ARG_OUTPUT_TARGET}")
    set(${ARG_OUTPUT_TARGET}_PREFIX_SCRIPT "${_script}" CACHE INTERNAL
        "Path to cmake/openssl-prefix-rename.sh used by ${ARG_OUTPUT_TARGET}")

    # Create placeholder files so Ninja dependency checking passes on clean
    # builds (the custom commands above will overwrite them with real content
    # on first build).
    if(NOT EXISTS "${_renamed_libssl}")
        file(WRITE "${_renamed_libssl}" "")
    endif()
    if(NOT EXISTS "${_renamed_libcrypto}")
        file(WRITE "${_renamed_libcrypto}" "")
    endif()

    message(STATUS "Configured prefixed OpenSSL archives (${ARG_OUTPUT_TARGET}):")
    message(STATUS "  Prefix:      ${ARG_PREFIX}")
    message(STATUS "  Syms file:   ${_syms_file}")
    message(STATUS "  libssl.a:    ${_renamed_libssl}")
    message(STATUS "  libcrypto.a: ${_renamed_libcrypto}")
endfunction()
