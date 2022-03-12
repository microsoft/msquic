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
$RootDir = Split-Path $PSScriptRoot -Parent

# Artifacts directory.
$ArtifactsDir = Join-Path $RootDir "artifacts"

# Output directory for all package files.
$PackageDir = Join-Path $ArtifactsDir "package"

$Configs = [System.Tuple]::Create("Debug","chk"), [System.Tuple]::Create("Release","fre")
$Archs = [System.Tuple]::Create("ARM","arm","arm"), [System.Tuple]::Create("ARM64","arm64","arm64"), `
         [System.Tuple]::Create("Win32","x86","x86"), [System.Tuple]::Create("x64","x64","amd64")

$SkipKernelArchs = @("Win32", "ARM")

function Force-Copy($Source, $Destination) {
    New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    Copy-Item $Source $Destination -Force | Out-Null
}

# Package up all necessary header and manifest files.
$IncFiles = "msquic.h", "msquicp.h", "msquic_winkernel.h", "msquic_winuser.h"

foreach ($Config in $Configs) {
    foreach ($Arch in $Archs) {
        $PlatformPackageDir = Join-Path $PackageDir "$($Arch.Item3)$($Config.Item2)"
        foreach ($File in $IncFiles) {
            Force-Copy (Join-Path $RootDir "src/inc/$File") $PlatformPackageDir
        }
        Force-Copy (Join-Path $RootDir "src/manifest/MsQuic.wprp") $PlatformPackageDir
        Force-Copy (Join-Path $RootDir "src/manifest/MsQuicEtw.man") $PlatformPackageDir

        $InputDir = Join-Path $ArtifactsDir "bin/windows/$($Arch.Item2)_$($Config.Item1)_schannel"
        Force-Copy (Join-Path $InputDir "msquic.lib") (Join-Path $PlatformPackageDir "lib/user")
        Force-Copy (Join-Path $InputDir "msquic.dll") (Join-Path $PlatformPackageDir "bin/user")
        Force-Copy (Join-Path $InputDir "msquic.pdb") (Join-Path $PlatformPackageDir "bin/user")
        Force-Copy (Join-Path $InputDir "msquictest.exe") (Join-Path $PlatformPackageDir "bin/user")
        Force-Copy (Join-Path $InputDir "msquictest.pdb") (Join-Path $PlatformPackageDir "bin/user")
        Force-Copy (Join-Path $InputDir "secnetperf.exe") (Join-Path $PlatformPackageDir "bin/user")
        Force-Copy (Join-Path $InputDir "secnetperf.pdb") (Join-Path $PlatformPackageDir "bin/user")

        if (!$SkipKernelArchs.Contains($Arch.Item1)) {
            $InputDir = Join-Path $ArtifactsDir "bin/winkernel/$($Arch.Item1)_$($Config.Item1)_schannel"
            Force-Copy (Join-Path $InputDir "msquic.lib") (Join-Path $PlatformPackageDir "lib/kernel")
            Force-Copy (Join-Path $InputDir "msquic.sys") (Join-Path $PlatformPackageDir "bin/kernel")
            Force-Copy (Join-Path $InputDir "msquic.pdb") (Join-Path $PlatformPackageDir "bin/kernel")
            Force-Copy (Join-Path $InputDir "msquictest.sys") (Join-Path $PlatformPackageDir "bin/kernel")
            Force-Copy (Join-Path $InputDir "msquictest.pdb") (Join-Path $PlatformPackageDir "bin/kernel")
            Force-Copy (Join-Path $InputDir "secnetperfdrv.sys") (Join-Path $PlatformPackageDir "bin/kernel")
            Force-Copy (Join-Path $InputDir "secnetperfdrv.pdb") (Join-Path $PlatformPackageDir "bin/kernel")
        }
    }

    # Special case chpe
    $ChpePackageDir = Join-Path $PackageDir "chpe$($Config.Item2)"
    foreach ($File in $IncFiles) {
        Force-Copy (Join-Path $RootDir "src/inc/$File") $ChpePackageDir
    }
    Force-Copy (Join-Path $RootDir "src/manifest/MsQuic.wprp") $ChpePackageDir
    Force-Copy (Join-Path $RootDir "src/manifest/MsQuicEtw.man") $ChpePackageDir
}
