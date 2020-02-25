<#

.SYNOPSIS
This packages up all code and binaries needed to create a VPack package to
ingest into the Windows OS build.

.EXAMPLE
    prepare-package.ps1

#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Artifacts directory.
$ArtifactsDir = Join-Path $RootDir "artifacts"

# Output directory for all package files.
$PackageDir = Join-Path $ArtifactsDir "package"

function Force-Copy($Source, $Destination) {
    New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    Copy-Item $Source $Destination -Force | Out-Null
}

# Package up all necessary header and manifest files.
$IncDir = Join-Path $PackageDir "inc"
$IncFiles = "msquic.h", "msquicp.h", "msquic_winkernel.h", "msquic_winuser.h"
foreach ($File in $IncFiles) {
    Force-Copy (Join-Path $RootDir "src" "inc" $File) $IncDir
}
Force-Copy (Join-Path $RootDir "src" "manifest" "MsQuic.wprp") $IncDir
Force-Copy (Join-Path $RootDir "src" "manifest" "MsQuicEtw.man") $IncDir

# Package up all the user mode binary files.
$Configs = [System.Tuple]::Create("Debug","chk"), [System.Tuple]::Create("Release","fre")
$Archs = [System.Tuple]::Create("x86","x86"), [System.Tuple]::Create("x64","amd64")
foreach ($Config in $Configs) {
    foreach ($Arch in $Archs) {
        $InputDir = Join-Path $ArtifactsDir "windows" "$($Arch.Item1)_$($Config.Item1)_schannel"
        $OutputDir = Join-Path $PackageDir "$($Arch.Item2)$($Config.Item2)"
        Force-Copy (Join-Path $InputDir "msquic.lib") (Join-Path $OutputDir "lib" "retail" "dll")
        Force-Copy (Join-Path $InputDir "msquic.dll") (Join-Path $OutputDir "bin")
        Force-Copy (Join-Path $InputDir "msquic.pdb") (Join-Path $OutputDir "symbols.pri" "retail" "dll")
        #Force-Copy (Join-Path $InputDir "msquictest.pdb") (Join-Path $OutputDir "symbols.pri" "test" "exe")
    }
}

# Package up all the kernel mode binary files.
$Configs = [System.Tuple]::Create("Debug","chk"), [System.Tuple]::Create("Release","fre")
$Archs = [System.Tuple]::Create("ARM","woa"), [System.Tuple]::Create("ARM64","ARM64"), `
         [System.Tuple]::Create("Win32","x86"), [System.Tuple]::Create("x64","amd64")
foreach ($Config in $Configs) {
    foreach ($Arch in $Archs) {
        $InputDir = Join-Path $ArtifactsDir "winkernel" "$($Arch.Item1)_$($Config.Item1)_schannel"
        $OutputDir = Join-Path $PackageDir "$($Arch.Item2)$($Config.Item2)"
        Force-Copy (Join-Path $InputDir "msquic.lib") (Join-Path $OutputDir "lib" "retail" "sys")
        Force-Copy (Join-Path $InputDir "msquic.sys") (Join-Path $OutputDir "bin")
        Force-Copy (Join-Path $InputDir "msquic.pdb") (Join-Path $OutputDir "symbols.pri" "retail" "sys")
    }
}
