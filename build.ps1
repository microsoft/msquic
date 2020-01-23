<#

.SYNOPSIS
This script provides helpers for building msquic.

.PARAMETER InstallDependencies
    Installs any necessary build dependencies.

.PARAMETER Config
    The debug or release build configuration to use.

.PARAMETER Tls
    The TLS library to use.

.PARAMETER DisableLogs
    Disables log collection.

.PARAMETER SanitizeAddress
    Enables address sanitizer.

.PARAMETER DisableTools
    Don't build the tools directory.

.PARAMETER DisableTest
    Don't build the test directory.

.PARAMETER Clean
    Deletes all previous build and configuration.

.EXAMPLE
    build.ps1 -InstallDependencies

.EXAMPLE
    build.ps1

.EXAMPLE
    build.ps1 -Config Release

#>

param (
    [Parameter(Mandatory = $false)]
    [switch]$InstallDependencies = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$DisableLogs = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SanitizeAddress = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTools = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTest = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Clean = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Important directory paths.
$CurrentDir = (Get-Item -Path ".\").FullName
$BaseArtifactsDir = Join-Path $CurrentDir "artifacts"
$BaseBuildDir = Join-Path $CurrentDir "bld"
$ArtifactsDir = $null
$BuildDir = $null
if ($IsWindows) {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "windows"
    $BuildDir = Join-Path $BaseBuildDir "windows"
} else {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "linux"
    $BuildDir = Join-Path $BaseBuildDir "linux"
}

if ($Clean) {
    # Delete old build/config directories.
    if (!(Test-Path $ArtifactsDir)) { Remove-Item $ArtifactsDir -Recurse -Force | Out-Null }
    if (!(Test-Path $BuildDir)) { Remove-Item $BuildDir -Recurse -Force | Out-Null }
}

# Initialize directories needed for building.
if (!(Test-Path $BaseBuildDir)) { mkdir $BaseBuildDir | Out-Null }
if (!(Test-Path $BuildDir)) { mkdir $BuildDir | Out-Null }

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

# Installs the dependencies.
function Install-Dependencies {
    if ($IsWindows) {

    } else {
        sudo apt-get install cmake
        sudo apt-get install build-essentials
        sudo apt-get install liblttng-ust-dev
        sudo apt-get install lttng-tools
    }
}

# Executes msquictext with the given arguments.
function CMake-Execute([String]$Arguments) {
    Push-Location $BuildDir | Out-Null
    try { Start-Process cmake $Arguments -Wait -NoNewWindow }
    finally { Pop-Location | Out-Null }
}

# Uses cmake to generate the build configuration files.
function CMake-Generate {
    $Arguments = "-g"
    if ($IsWindows) {
        $Arguments += " 'Visual Studio 16 2019' -A x64"
    } else {
        $Arguments += " 'Linux Makefiles'"
    }
    switch ($Config) {
        "schannel" { $Arguments += " -DQUIC_TLS=schannel" }
        "openssl"  { $Arguments += " -DQUIC_TLS=openssl" }
        "stub"     { $Arguments += " -DQUIC_TLS=stub" }
        "mitls"    { $Arguments += " -DQUIC_TLS=mitls" }
        ""         { }
    }
    if ($DisableLogs) {
        $Arguments += " -DQUIC_ENABLE_LOGGING=off"
    }
    if ($SanitizeAddress) {
        $Arguments += " -DQUIC_SANITIZE_ADDRESS=on"
    }
    if ($DisableTools) {
        $Arguments += " -DQUIC_BUILD_TOOLS=off"
    }
    if ($DisableTest) {
        $Arguments += " -DQUIC_BUILD_TEST=off"
    }
    $Arguments += " ../.."

    CMake-Execute $Arguments
}

# Uses cmake to generate the build configuration files.
function CMake-Build {
    $Arguments = "--build ."
    switch ($Config) {
        "Debug"    { $Arguments += " --config DEBUG" }
        "Release"  { $Arguments += " --config RELEASE" }
    }

    CMake-Execute $Arguments
}

##############################################################
#                     Main Execution                         #
##############################################################

if ($InstallDependencies) {
    Log "Installing dependencies..."
    Install-Dependencies
    exit
}

# Generate the build files.
Log "Generating files..."
CMake-Generate

# Build the code.
Log "Building..."
CMake-Build

Log "Done."
