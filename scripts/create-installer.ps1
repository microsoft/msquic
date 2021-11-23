<#

.SYNOPSIS
This script creates a Windows .msi installer file.

.PARAMETER Arch
    The CPU architecture to build for.

.PARAMETER Tls
    The TLS library to use.

.EXAMPLE
    create-installer.ps1

.EXAMPLE
    create-installer.ps1 -Tls openssl -Arch x86

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64", "arm64ec")]
    [string]$Arch = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
    [string]$Tls = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if (!$IsWindows) {
    Write-Error "Only supported on Windows"
    exit
}

$BuildConfig = & (Join-Path $PSScriptRoot get-buildconfig.ps1) -Platform "windows" -Tls $Tls -Arch $Arch -Config "Release"

$Platform = $BuildConfig.Platform
$Tls = $BuildConfig.Tls
$Arch = $BuildConfig.Arch
$ArtifactsDir = $BuildConfig.ArtifactsDir

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$ScriptsDir = Join-Path $RootDir "scripts"
$BaseArtifactsDir = Join-Path $RootDir "artifacts"
$DistDir = Join-Path $BaseArtifactsDir "dist"

# Important directory paths.
$BaseBuildDir = Join-Path $RootDir "build"
$BuildDir = Join-Path $BaseBuildDir $Platform
$BuildDir = Join-Path $BuildDir "$($Arch)_$($Tls)"

if (!(Test-Path $DistDir)) {
    New-Item -Path $DistDir -ItemType Directory -Force | Out-Null
}

candle.exe (Join-Path $ScriptsDir "installer.wxs") -o (Join-Path $BuildDir "msquic.wixobj")
light.exe -b $ArtifactsDir -o (Join-Path $DistDir "msquic_$($Tls)_$Arch.msi") (Join-Path $BuildDir "msquic.wixobj")
