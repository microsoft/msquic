<#

.SYNOPSIS
This script provides helpers for running executing the language interop tests tests.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.PARAMETER ExtraArtifactDir
    Add an extra classifier to the artifact directory to allow publishing alternate builds of same base library

.PARAMETER Languages
    The languages to run.

.PARAMETER IsolationMode
    Controls the isolation mode when running each test case.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER NoProgress
    Disables the progress bar.

.Parameter AZP
    Runs in Azure Pipelines mode.

.EXAMPLE
    run-language-interop.ps1

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [string]$Languages = "dotnet",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Batch", "Isolated")]
    [string]$IsolationMode = "Batch",

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$NoProgress = $false,

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$AZP = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

if ($IsWindows) {
    $Platform = "windows"
} elseif ($IsLinux) {
    $Platform = "linux"
} elseif ($IsMacOS) {
    $Platform = "macos"
} else {
    Write-Error "Unsupported platform type!"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$ArtifactDir = Join-Path $RootDir artifacts bin $Platform "$($Arch)_$($Config)_$($Tls)"
if ($IsWindows) {
    $MsQuicArtifact = Join-Path $ArtifactDir msquic.dll
} elseif ($IsMacOS) {
    $MsQuicArtifact = Join-Path $ArtifactDir libmsquic.dylib
} else {
    $MsQuicArtifact = Join-Path $ArtifactDir libmsquic.so
}

if ($Languages.Contains("dotnet")) {
    $DotNetPath = Join-Path $RootDir src cs
    $DotNetSolution = Join-Path $DotNetPath MsQuicNet.sln
    $TestApp = Join-Path $DotNetPath tool MsQuicTool.csproj
    dotnet build $DotNetSolution

    Write-Host "Running Test"
    dotnet run --project $TestApp $MsQuicArtifact
}
