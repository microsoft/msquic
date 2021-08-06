<#

.SYNOPSIS
    This script assembles the archives into a distribution.

.PARAMETER Config
    The debug or release configuration to build for.

.PARAMETER Tls
    The TLS library to use.
#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
    [string]$Tls = "openssl"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Find all types we can archive
$BaseArtifactsDir = Join-Path $RootDir "artifacts"
$PlatformDir = Join-Path $BaseArtifactsDir "bin/windows"

$PackagingDir = Join-Path $BaseArtifactsDir "temp/nuget"

if ((Test-Path $PackagingDir)) {
    Remove-Item -Path "$PackagingDir/*" -Recurse -Force
}

# Arm is ignored, as there are no shipping arm devices
$Architectures = "x64","x86","arm64"

# Copy artifacts to correct folders
$NativeDir = Join-Path $PackagingDir "build/native"

foreach ($Arch in $Architectures) {
    $BuildPath = Join-Path $PlatformDir "$($Arch)_$($Config)_$($Tls)"
    $LibPath = Join-Path $NativeDir "lib/$Arch"
    $BinPath = Join-Path $NativeDir "bin/$Arch"

    if (!(Test-Path $LibPath)) {
        New-Item -Path $LibPath -ItemType Directory -Force | Out-Null
    }

    if (!(Test-Path $BinPath)) {
        New-Item -Path $BinPath -ItemType Directory -Force | Out-Null
    }

    Copy-Item (Join-Path $BuildPath msquic.dll) $BinPath
    Copy-Item (Join-Path $BuildPath msquic.pdb) $BinPath
    Copy-Item (Join-Path $BuildPath msquic.lib) $LibPath
}

$HeaderDir = Join-Path $RootDir "src/inc"
$Headers = @(Join-Path $HeaderDir "msquic.h")
$Headers += Join-Path $HeaderDir  "msquic_winuser.h"

$IncludePath = Join-Path $NativeDir "include"
if (!(Test-Path $IncludePath)) {
    New-Item -Path $IncludePath -ItemType Directory -Force | Out-Null
}

foreach ($Header in $Headers) {
    $FileName = Split-Path -Path $Header -Leaf
    $CopyToFolder = (Join-Path $IncludePath $FileName)
    Copy-Item -LiteralPath $Header -Destination $CopyToFolder -Force
}

Copy-Item (Join-Path $RootDir LICENSE) $PackagingDir
if ($Tls -like "openssl") {
    # Only need license, no 3rd party code
    Copy-Item -Path (Join-Path $RootDir "THIRD-PARTY-NOTICES") -Destination $PackagingDir
}

$NugetSourceFolder = Join-Path $RootDir "src/nuget"

Copy-Item (Join-Path $NugetSourceFolder "msquic-$Tls.nuspec") $PackagingDir
Copy-Item (Join-Path $NugetSourceFolder "msquic-$Tls.targets") $NativeDir

$DistDir = Join-Path $BaseArtifactsDir "dist"

nuget.exe pack (Join-Path $PackagingDir "msquic-$Tls.nuspec") -OutputDirectory $DistDir
