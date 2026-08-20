# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include(FindPackageHandleStandardArgs)

set(
    QUIC_NUGET_PACKAGES
    "${CMAKE_CURRENT_SOURCE_DIR}/packages"
    CACHE PATH
    "Directory containing repository-local NuGet packages")

file(
    READ
    "${CMAKE_CURRENT_SOURCE_DIR}/packages.config"
    XDP_SDK_PACKAGES)
string(
    REGEX MATCH
    "<package[^>]*id=\"Microsoft\\.XDP-for-Windows\\.Sdk\"[^>]*version=\"([^\"]+)\""
    XDP_SDK_PACKAGE_VERSION
    "${XDP_SDK_PACKAGES}")
set(XdpSdk_VERSION "${CMAKE_MATCH_1}")

find_path(
    XdpSdk_INCLUDE_DIR
    NAMES xdpapi.h
    PATHS
        "${QUIC_NUGET_PACKAGES}/Microsoft.XDP-for-Windows.Sdk.${XdpSdk_VERSION}/build/native/include"
    NO_DEFAULT_PATH)

find_package_handle_standard_args(
    XdpSdk
    REQUIRED_VARS XdpSdk_INCLUDE_DIR XdpSdk_VERSION
    VERSION_VAR XdpSdk_VERSION)

if(XdpSdk_FOUND AND NOT TARGET XdpSdk::Headers)
    add_library(XdpSdk::Headers INTERFACE IMPORTED)
    set_target_properties(
        XdpSdk::Headers
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${XdpSdk_INCLUDE_DIR}")
endif()

set(XDP_INCLUDE_DIR "${XdpSdk_INCLUDE_DIR}")
