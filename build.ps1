<#

.SYNOPSIS
This script provides helpers for building msquic.

.PARAMETER InstallDependencies
    Runs the test cases serially instead of in parallel. Required for log collection.

.PARAMETER Config
    Compresses the output files generated for failed test cases.

.PARAMETER Tls
    The name of the profile to use for log collection.

.PARAMETER DisableLogs
    A filter to include test cases from the list to execute.

.PARAMETER SanitizeAddress
    A filter to remove test cases from the list to execute.

.PARAMETER DisableTools
    Don't build the tools directory.

.PARAMETER DisableTest
    Don't build the test directory.

.EXAMPLE
    build.ps1

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
    [switch]$DisableTest = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Current directory.
$CurrentDir = (Get-Item -Path ".\").FullName

# Path for the build directory.
$BuildDir = Join-Path $CurrentDir "bld"
if (!(Test-Path $BuildDir)) { mkdir $BuildDir | Out-Null }

# Add the platform specific path.
if ($IsWindows) {
    $BuildDir = Join-Path $BuildDir "windows"
} else {
    $BuildDir = Join-Path $BuildDir "linux"
}
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
function Start-CMake([String]$Arguments) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "cmake"
    $pinfo.Arguments = $Arguments
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.WorkingDirectory = $BuildDir
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p
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
    $Arguments += " $($CurrentDir)"

    $p = Start-CMake $Arguments
    $stdout = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    $stdout
}

# Uses cmake to generate the build configuration files.
function CMake-Build {
    $Arguments = "--build ."
    switch ($Config) {
        "Debug"    { $Arguments += " --config DEBUG" }
        "Release"  { $Arguments += " --config RELEASE" }
    }

    $p = Start-CMake $Arguments
    $stdout = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    $stdout
}

######################
#   Main Execution   #
######################

if ($InstallDependencies) {
    Log "Installing dependencies..."
    Install-Dependencies
}

# Generate the build files.
Log "Generating files..."
CMake-Generate

# Build the code.
Log "Building..."
CMake-Build
