<#

.SYNOPSIS
Updates the CLOG sidecar file after adding new trace calls to source files.

.DESCRIPTION
Run this script after adding new QuicTraceEvent/QuicTraceLog* calls. It
updates src/manifest/clog.sidecar with the new event signatures, which must
be committed alongside the source changes.

The cmake build system validates the sidecar at configure time using
--readOnly mode. If you add a new trace call without updating the sidecar,
cmake configure will fail. Use this script (or the cmake update_clog_sidecar
target) to update the sidecar and then re-run cmake.

Alternatively, if cmake is already configured, you can run:
    cmake --build <build_dir> --target update_clog_sidecar

#>

#Requires -Version 7.2

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Change directory to the same directory as this script;  storing our original directory for later
$OrigDir = Get-Location
Set-Location $PSScriptRoot
$RootDir = Split-Path $PSScriptRoot -Parent
$SrcDir = Join-Path $RootDir "src"

$Sidecar = Join-Path $SrcDir "manifest" "clog.sidecar"
$ConfigFile = Join-Path $SrcDir "manifest" "msquic.clog_config"

$TmpOutputDir = Join-Path $RootDir "build" "tmp"
$ClogDir = Join-Path $RootDir "build" "clog"

# Build CLOG, placing results into the CLOG directory under our build directory
dotnet publish ../submodules/clog/src/clog -o ${ClogDir} -f net8.0

#
# You may be tempted to delete the sidecar - DO NOT DO THIS - the sidecar
#     exists for several purposes - one of those is to verify signatures of trace calls have
#     not changed.  If you delete the sidecar, you'll miss errors that may save you broken contracts
#     that occur when you decode
#

$allFiles = ""
$allFiles = Get-Content ./clog.inputs

foreach ($File in $allFiles) {
    Write-Debug "Add file: $File"
    $allFiles = $allFiles + " " + $File
}

#
# Allow the sidecar to run on a newer .NET version.
#
$OriginalDOTNET_ROLL_FORWARD = $env:DOTNET_ROLL_FORWARD

try {
    $env:DOTNET_ROLL_FORWARD = "Major"
    # Generate code for all different platform profiles, updating the sidecar with any new
    # trace events. All generated stub/header output goes to a temporary directory and is
    # not committed. The cmake build system generates platform-specific files at configure
    # time using --readOnly mode from the updated sidecar.
    Invoke-Expression "${ClogDir}/clog -p windows --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir/windows --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p windows_kernel --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir/windows_kernel --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p stubs --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir/stubs --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p linux --dynamicTracepointProvider --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir/linux --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p macos --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir/macos --inputFiles $allFiles"
} finally {
    $env:DOTNET_ROLL_FORWARD = $OriginalDOTNET_ROLL_FORWARD
}

Write-Host ""
Write-Host "Sidecar updated. Commit $Sidecar along with your source changes."
Write-Host "Re-run cmake configure so the build system picks up the new sidecar."

# Return to where we started
Set-Location $OrigDir
