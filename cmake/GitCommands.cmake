# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

find_package(Git QUIET)
if (NOT Git_FOUND)
    message(STATUS "Unable to find git, which is needed for versioning")
endif()

function(get_git_dir DIRECTORY OUTPUT_VAR)
    execute_process(
        COMMAND
            ${GIT_EXECUTABLE} rev-parse --git-dir
        WORKING_DIRECTORY
            ${DIRECTORY}
        RESULT_VARIABLE
            GIT_DIR_RESULT
        OUTPUT_VARIABLE
            GIT_DIR_OUTPUT
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Allow to fail
    set(${OUTPUT_VAR} ${GIT_DIR_OUTPUT} PARENT_SCOPE)
endfunction()

function(get_git_current_hash DIRECTORY OUTPUT_VAR)
    execute_process(
        COMMAND
            ${GIT_EXECUTABLE} rev-parse --verify HEAD
        WORKING_DIRECTORY
            ${DIRECTORY}
        RESULT_VARIABLE
            GIT_CURRENT_HASH_RESULT
        OUTPUT_VARIABLE
            GIT_CURRENT_HASH_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT ("${GIT_CURRENT_HASH_RESULT}" STREQUAL "0"))
        message(STATUS ${GIT_CURRENT_HASH_OUTPUT})
        message(STATUS "Failed to get ${DIRECTORY} git hash")
    else()
        set(${OUTPUT_VAR} ${GIT_CURRENT_HASH_OUTPUT} PARENT_SCOPE)
    endif()
endfunction()

function(get_git_remote_url DIRECTORY OUTPUT_VAR)
    execute_process(
        COMMAND
            ${GIT_EXECUTABLE} config --get remote.origin.url
        RESULT_VARIABLE
            GIT_REMOTE_URL_RESULT
        OUTPUT_VARIABLE
            GIT_REMOTE_URL_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        WORKING_DIRECTORY
            ${DIRECTORY}
    )

    if (NOT ("${GIT_REMOTE_URL_RESULT}" STREQUAL "0"))
        message(${GIT_REMOTE_URL_OUTPUT})
        message(FATAL_ERROR "Failed to get ${DIRECTORY} git remote")
    endif()

    set(${OUTPUT_VAR} ${GIT_REMOTE_URL_OUTPUT} PARENT_SCOPE)
endfunction()

function(run_git_submodule_foreach CMD DIRECTORY OUTPUT_VALUE)
    execute_process(
        COMMAND
            ${GIT_EXECUTABLE} submodule foreach --quiet --recursive "${CMD}"
        RESULT_VARIABLE
            GIT_SUBMODULE_CMD_RESULT
        OUTPUT_VARIABLE
            GIT_SUBMODULE_CMD_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        WORKING_DIRECTORY
            ${DIRECTORY}
    )

    if (NOT ("${GIT_SUBMODULE_CMD_RESULT}" STREQUAL "0"))
        message(${GIT_SUBMODULE_CMD_OUTPUT})
        message(FATAL_ERROR "Failed to run git submodule foreach command: ${CMD} in ${DIRECTORY}")
    endif()
    set(${OUTPUT_VALUE} ${GIT_SUBMODULE_CMD_OUTPUT} PARENT_SCOPE)
endfunction()
