<#

.SYNOPSIS
    This script assembles the archives into a distribution.


#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Find all types we can archive
$BaseArtifactsDir = Join-Path $RootDir "artifacts"
$ArtifactsBinDir = Join-Path $BaseArtifactsDir "bin"

# All direct subfolders are OS's
$Platforms = Get-ChildItem -Path $ArtifactsBinDir

$WindowsBuilds = @()
$AllBuilds = @()

foreach ($Platform in $Platforms) {
    $PlatBuilds = Get-ChildItem -Path $Platform
    foreach ($PlatBuild in $PlatBuilds) {
        $AllBuilds += $PlatBuild
        if ($Platform.Name -eq "windows") {
            $WindowsBuilds += $PlatBuild
        }
    }
}

foreach ($Build in $AllBuilds) {
    $BuildBaseName = $Build.Name
    $Platform = Split-Path -Path (Split-Path -Path $Build -Parent) -Leaf

    if ($Platform -eq "winkernel") {
        continue
    }

    # Important directory paths.
    $ArtifactsDir = $Build.FullName

    $DistDir = Join-Path $BaseArtifactsDir "dist"

    $TempDir = Join-Path $BaseArtifactsDir "temp" "zip" $Platform
    $TempDir = Join-Path $TempDir $BuildBaseName

    # Initialize directories needed for building.
    if (!(Test-Path $DistDir)) {
        New-Item -Path $DistDir -ItemType Directory -Force | Out-Null
    }

    if ((Test-Path $TempDir)) {
        Remove-Item -Path "$TempDir/*" -Recurse -Force
    }

    New-Item -Path $TempDir -ItemType Directory -Force | Out-Null

    $HeaderDir = Join-Path $RootDir "src" "inc"

    # Find Headers

    $Headers = @(Join-Path $HeaderDir "msquic.h")

    if ($Platform -eq "windows" -or $Platform -eq "uwp") {
        $Headers += Join-Path $HeaderDir  "msquic_winuser.h"
    } else {
        $Headers += Join-Path $HeaderDir  "msquic_linux.h"
        $Headers += Join-Path $HeaderDir  "quic_sal_stub.h"
    }

    # Find Binaries

    $Binaries = @()

    if ($Platform -eq "windows" -or $Platform -eq "uwp") {
        $Binaries += Join-Path $ArtifactsDir "msquic.dll"
        $Binaries += Join-Path $ArtifactsDir "msquic.pdb"
    } else {
        $Binaries += Join-Path $ArtifactsDir "libmsquic.so"
        $LttngBin = Join-Path $ArtifactsDir "libmsquic.lttng.so"
        if (Test-Path $LttngBin) {
            $Binaries += $LttngBin
        }
    }

    $Libraries = @()

    if ($Platform -eq "windows" -or $Platform -eq "uwp") {
        $Libraries += Join-Path $ArtifactsDir "msquic.lib"
    }

    # Copy items into temp folder that can be zipped in 1 command

    $IncludeDir = Join-Path $TempDir "include"
    New-Item -Path $IncludeDir -ItemType Directory -Force | Out-Null

    $BinFolder = Join-Path $TempDir "bin"
    New-Item -Path $BinFolder -ItemType Directory -Force | Out-Null

    $LibFolder = Join-Path $TempDir "lib"
    New-Item -Path $LibFolder -ItemType Directory -Force | Out-Null

    foreach ($Header in $Headers) {
        $FileName = Split-Path -Path $Header -Leaf
        $CopyToFolder = (Join-Path $IncludeDir $FileName)
        Copy-Item -LiteralPath $Header -Destination $CopyToFolder -Force
    }

    foreach ($Binary in $Binaries) {
        $FileName = Split-Path -Path $Binary -Leaf
        $CopyToFolder = (Join-Path $BinFolder $FileName)
        Copy-Item -LiteralPath $Binary -Destination $CopyToFolder -Force
    }

    foreach ($Library in $Libraries) {
        $FileName = Split-Path -Path $Library -Leaf
        $CopyToFolder = (Join-Path $LibFolder $FileName)
        Copy-Item -LiteralPath $Library -Destination $CopyToFolder -Force
    }

    # Package zip archive
    Compress-Archive -Path "$TempDir/*" -DestinationPath (Join-Path $DistDir "msquic_$($Platform)_$BuildBaseName.zip") -Force
}
