# CMake Module to generate Source Link JSON for the MSVC compiler
#
# Microsoft defines Source Link as the following:
#
# > Source Link is a developer productivity feature that allows unique
# > information about an assembly's original source code to be embedded in its
# > PDB during compilation.
# https://github.com/dotnet/designs/blob/master/accepted/diagnostics/source-link.md
#
# Specifically, this script will embedded information into the PDB of where to
# download the source code from. This will allow developers to use the PDB without
# the source located on disk.
#
# This script currently only works with GitHub but could be extended to support
# other source control servers. Any server which hosts their code as raw source
# over HTTP should work.
#
include(${CMAKE_CURRENT_LIST_DIR}/GitCommands.cmake)

# Warn if this is included and the compilier doesn't support source link
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
    if ("${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER_EQUAL "19.20")
        # Good to go!
    elseif("${CMAKE_C_COMPILER_VERSION}" VERSION_GREATER_EQUAL "19.14")
        message(STATUS "SourceLink enabled but case insensative")
    else()
        message(WARNING "SourceLink will not work on version of MSVC less than 19.14")
    endif()
else()
    message(WARNING "SourceLink will not work on the ${CMAKE_C_COMPILER_ID} compiler")
endif()

# REPO_ROOT is the path to the repository where code it stored.
#
# SOURCE_LINK_JSON_PATH is the file to output the json
function(source_link REPO_ROOT SOURCE_LINK_JSON_PATH SOURCE_LINK_JSON_INPUT_PATH)
    if (NOT (IS_DIRECTORY ${REPO_ROOT}))
        message(FATAL_ERROR "\"${REPO_ROOT}\" is not a directory")
    endif()

    get_git_remote_url(${REPO_ROOT} GIT_REMOTE)
    get_git_current_hash(${REPO_ROOT} GIT_CURRENT_HASH)

    build_source_link_rule(${REPO_ROOT} ${GIT_REMOTE} ${GIT_CURRENT_HASH} ROOT_RULE)

    set(SOURCE_LINK_RULES)
    list(APPEND SOURCE_LINK_RULES ${ROOT_RULE})

    # Also build rules for submodules
    run_git_submodule_foreach("echo $displaypath,$sha1,`git config --get remote.origin.url`" ${REPO_ROOT} SUBMODULE_INFO)

    if (NOT ("${SUBMODULE_INFO}" STREQUAL ""))
        # Turn output of new lines into a CMake list
        string(REPLACE "\r\n" ";" SUBMODULE_INFO ${SUBMODULE_INFO})
        string(REPLACE "\n" ";" SUBMODULE_INFO ${SUBMODULE_INFO})

        foreach(ITEM ${SUBMODULE_INFO})
            # Turn each line into a list of path;hash;url
            string(REPLACE "," ";" SUBMODULE ${ITEM})
            list(GET SUBMODULE 0 LOCAL_PATH)
            list(GET SUBMODULE 1 CURRENT_HASH)
            list(GET SUBMODULE 2 REMOTE)
            string(CONCAT LOCAL_PATH "${REPO_ROOT}/" ${LOCAL_PATH})
            build_source_link_rule(${LOCAL_PATH} ${REMOTE} ${CURRENT_HASH} RULE)
            list(APPEND SOURCE_LINK_RULES ${RULE})
        endforeach()
    endif()

    set(OUTPUT)
    string(APPEND OUTPUT "{\n")
    string(APPEND OUTPUT "\"documents\": {\n")
    string(JOIN ",\n" EXPANDED_RULES ${SOURCE_LINK_RULES})
    string(APPEND OUTPUT "${EXPANDED_RULES}\n")
    string(APPEND OUTPUT "}\n")
    string(APPEND OUTPUT "}\n")

    configure_file(${SOURCE_LINK_JSON_INPUT_PATH} ${SOURCE_LINK_JSON_PATH})

endfunction()

function(build_source_link_rule LOCAL_PATH GIT_REMOTE GIT_CURRENT_HASH OUTPUT)
    # Verify local path exists
    if (NOT (IS_DIRECTORY ${LOCAL_PATH}))
        message(FATAL_ERROR "${LOCAL_PATH} is not a directory")
    endif()

    # Change local path to native path
    file(TO_NATIVE_PATH "${LOCAL_PATH}/*" LOCAL_PATH)
    # Escape any backslashes for JSON
    string(REPLACE "\\" "\\\\" LOCAL_PATH ${LOCAL_PATH})

    # If this is an mscodehub URL, replace with the equivalent GitHub URL.
    if (("${GIT_REMOTE}" MATCHES "https://mscodehub\\.visualstudio\\.com/msquic/_git/msquic"))
        set(GIT_REMOTE "https://github.com/microsoft/msquic")
    endif()

    # If this is an mscodehub dev URL, replace with the equivalent GitHub URL.
    if (("${GIT_REMOTE}" MATCHES "https://dev\\.azure\\.com/mscodehub/_git/msquic"))
        set(GIT_REMOTE "https://github.com/microsoft/msquic")
    endif()

    # Verify this is a GitHub URL
    # In the future we could support other source servers but currently they
    # are not supported
    if (NOT ("${GIT_REMOTE}" MATCHES "https://github\\.com"))
        message(STATUS "Unable to sourcelink remote: \"${GIT_REMOTE}\". Unknown host")
        return()
    endif()

    string(REPLACE ".git" "" RAW_GIT_URL ${GIT_REMOTE})
    string(REPLACE "github.com" "raw.githubusercontent.com" RAW_GIT_URL ${RAW_GIT_URL})
    string(CONCAT RAW_GIT_URL ${RAW_GIT_URL} "/${GIT_CURRENT_HASH}/*")

    set(${OUTPUT} "\"${LOCAL_PATH}\" : \"${RAW_GIT_URL}\"" PARENT_SCOPE)

endfunction(build_source_link_rule)
