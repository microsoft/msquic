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

$Version = "2.1.0"

$WindowsBuilds = @()
$AllBuilds = @()

foreach ($Platform in $Platforms) {
    $PlatBuilds = Get-ChildItem -Path $Platform.FullName
    foreach ($PlatBuild in $PlatBuilds) {
        if (!(Test-Path $PlatBuild.FullName -PathType Container)) {
            continue;
        }
        if ($PlatBuild.Name -eq "_manifest") {
            continue;
        }
        $AllBuilds += $PlatBuild
        if ($Platform.Name -eq "windows") {
            $WindowsBuilds += $PlatBuild
        }
    }
}

foreach ($Build in $AllBuilds) {
    $BuildBaseName = $Build.Name
    $Platform = Split-Path -Path (Split-Path -Path $Build.FullName -Parent) -Leaf

    if ($Platform -eq "winkernel") {
        continue
    }

    # Important directory paths.
    $ArtifactsDir = $Build.FullName

    $DistDir = Join-Path $BaseArtifactsDir "dist"

    $TempDir = Join-Path $BaseArtifactsDir "temp/zip/$Platform"
    $TempDir = Join-Path $TempDir $BuildBaseName

    # Initialize directories needed for building.
    if (!(Test-Path $DistDir)) {
        New-Item -Path $DistDir -ItemType Directory -Force | Out-Null
    }

    if ((Test-Path $TempDir)) {
        Remove-Item -Path "$TempDir/*" -Recurse -Force
    }

    New-Item -Path $TempDir -ItemType Directory -Force | Out-Null

    $HeaderDir = Join-Path $RootDir "src/inc"

    # Find Headers

    $Headers = @(Join-Path $HeaderDir "msquic.h")

    if ($Platform -eq "windows" -or $Platform -eq "uwp" -or $Platform -eq "gamecore_console") {
        $Headers += Join-Path $HeaderDir  "msquic_winuser.h"
    } else {
        $Headers += Join-Path $HeaderDir  "msquic_posix.h"
        $Headers += Join-Path $HeaderDir  "quic_sal_stub.h"
    }

    # Find Binaries

    $Binaries = @()
    $DebugFolders = @()
    $TestBinary = ""

    if ($Platform -eq "windows" -or $Platform -eq "uwp" -or $Platform -eq "gamecore_console") {
        $Binaries += Join-Path $ArtifactsDir "msquic.dll"
        $Binaries += Join-Path $ArtifactsDir "msquic.pdb"
        if ($Platform -eq "windows") {
            $TestBinary = Join-Path $ArtifactsDir "msquictest.exe"
        }
    } elseif ($Platform -eq "linux") {
        $Binaries += Join-Path $ArtifactsDir "libmsquic.so.$Version"
        $LttngBin = Join-Path $ArtifactsDir "libmsquic.lttng.so.$Version"
        if (Test-Path $LttngBin) {
            $Binaries += $LttngBin
        }
        $TestBinary = Join-Path $ArtifactsDir "msquictest"
    } else {
        # macos
        $Binaries += Join-Path $ArtifactsDir "libmsquic.$Version.dylib"
        $DebugFolder = Join-Path $ArtifactsDir "libmsquic.$Version.dylib.dSYM"
        if (Test-Path $DebugFolder) {
            $DebugFolders += $DebugFolder
        }
        $TestBinary = Join-Path $ArtifactsDir "msquictest"
    }

    $Libraries = @()

    if ($Platform -eq "windows" -or $Platform -eq "uwp" -or $Platform -eq "gamecore_console") {
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

    foreach ($DebugFolder in $DebugFolders) {
        Copy-Item -Path $DebugFolder -Destination $BinFolder -Recurse
    }

    foreach ($Library in $Libraries) {
        $FileName = Split-Path -Path $Library -Leaf
        $CopyToFolder = (Join-Path $LibFolder $FileName)
        Copy-Item -LiteralPath $Library -Destination $CopyToFolder -Force
    }

    # Copy License
    Copy-Item -Path (Join-Path $RootDir "LICENSE") -Destination $TempDir
    if (!($BuildBaseName -like "*schannel*")) {
        # Only need license, no 3rd party code
        Copy-Item -Path (Join-Path $RootDir "THIRD-PARTY-NOTICES") -Destination $TempDir
    }

    # Package zip archive
    Compress-Archive -Path "$TempDir/*" -DestinationPath (Join-Path $DistDir "msquic_$($Platform)_$BuildBaseName.zip") -Force

    # For now, package only x64 Release binaries
    if ($Platform -eq "linux" -and $BuildBaseName -like "*x64_Release*") {
        Write-Output "Packaging $Build"
        $OldLoc = Get-Location
        Set-Location $RootDir
        & $RootDir/scripts/make-packages.sh --output $DistDir
        Set-Location $OldLoc
    }

    # Package msquictest in separate test package.
    if ($TestBinary -ne "") {
        Compress-Archive -Path $TestBinary -DestinationPath (Join-Path $DistDir "msquic_$($Platform)_$($BuildBaseName)_test.zip") -Force
    }
}
