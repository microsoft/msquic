<#

.SYNOPSIS
    This script runs .NET tests using previously built MsQuic binaries

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64", "universal")]
    [string]$Arch = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$BuildConfig = & (Join-Path $PSScriptRoot get-buildconfig.ps1) -Tls $Tls -Arch $Arch -ExtraArtifactDir $ExtraArtifactDir -Config $Config

$Tls = $BuildConfig.Tls
$Arch = $BuildConfig.Arch
$RootArtifactDir = $BuildConfig.ArtifactsDir

if ($IsWindows) {
    $LibName = "msquic.dll"
} elseif ($IsMacOS) {
    $LibName = "libmsquic.dylib"
} else {
    $LibName = "libmsquic.so"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

dotnet build (Join-Path $RootDir src cs)
dotnet run --project (Join-Path $RootDir src cs tool) -- (Join-Path $RootArtifactDir $LibName)
