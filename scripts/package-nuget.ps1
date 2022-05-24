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
    [string]$Tls = "openssl",

    [Parameter(Mandatory = $false)]
    [switch]$UWP = $false,

    [Parameter(Mandatory = $false)]
    [switch]$XDP = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ReleaseBuild = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Get-GitHash {
    param ($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RepoDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentCommitHash = $null
    try {
        $CurrentCommitHash = git rev-parse HEAD
    } catch {
        Write-LogAndDebug "Failed to get commit hash from git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $CurrentCommitHash
}

function Get-GitRemote {
    param ($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RepoDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $RepoRemote = $null
    try {
        $RepoRemote = git config --get remote.origin.url
    } catch {
        Write-LogAndDebug "Failed to get commit repo from git"
        $RepoRemote = "https://github.com/microsoft/msquic.git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $RepoRemote
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Find all types we can archive
$BaseArtifactsDir = Join-Path $RootDir "artifacts"

if ($UWP) {
    $PlatformDir = Join-Path $BaseArtifactsDir "bin/uwp"
} else {
    $PlatformDir = Join-Path $BaseArtifactsDir "bin/windows"
}

$PackagingDir = Join-Path $BaseArtifactsDir "temp/nuget"

if ((Test-Path $PackagingDir)) {
    Remove-Item -Path "$PackagingDir/*" -Recurse -Force
}

# Arm is ignored, as there are no shipping arm devices
$Architectures = "x64","x86","arm64"

if ($XDP) {
    # XDP only supports x64
    $Architectures = "x64"
}

# Copy artifacts to correct folders
$NativeDir = Join-Path $PackagingDir "build/native"

foreach ($Arch in $Architectures) {
    $BuildPath = Join-Path $PlatformDir "$($Arch)_$($Config)_$($Tls)"
    if ($XDP) {
        $BuildPath += "_xdp"
    }
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

$NugetSourceFolder = Join-Path $RootDir "src/distribution"

if ($UWP) {
    $PackageName = "Microsoft.Native.Quic.MsQuic.UWP.$Tls"
} elseif ($XDP) {
    Copy-Item -Path (Join-Path $PSScriptRoot xdp-devkit.json) -Destination (Join-Path $PackagingDir xdp-devkit-temp.json)
    $PackageName = "Microsoft.Native.Quic.MsQuic.XDP.$Tls"
} else {
    $PackageName = "Microsoft.Native.Quic.MsQuic.$Tls"
}

Copy-Item (Join-Path $NugetSourceFolder "$PackageName.nuspec") $PackagingDir
Copy-Item (Join-Path $NugetSourceFolder "$PackageName.targets") $NativeDir

Copy-Item (Join-Path $NugetSourceFolder "pkgicon.png") $PackagingDir

$DistDir = Join-Path $BaseArtifactsDir "dist"

$CurrentCommitHash = Get-GitHash -RepoDir $RootDir
$RepoRemote = Get-GitRemote -RepoDir $RootDir

$Version = "2.1.0"

$BuildId = $env:BUILD_BUILDID
if ($null -ne $BuildId) {
    if ($ReleaseBuild) {
        $Version += "+$BuildId"
    } else {
        $Version += "-ci.$BuildId"
    }
} else {
    $Version += "-local"
}

Write-Host $Version

nuget.exe pack (Join-Path $PackagingDir "$PackageName.nuspec") -OutputDirectory $DistDir -p CommitHash=$CurrentCommitHash -p RepoRemote=$RepoRemote -Version $Version
