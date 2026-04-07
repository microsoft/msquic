<#

.SYNOPSIS
This regenerates the CLOG sidecar file.

#>

#Requires -Version 7.2

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

class SimpleStringComparer:Collections.Generic.IComparer[string] {
    [Globalization.CompareInfo]$CompareInfo = [Globalization.CompareInfo]::GetCompareInfo([CultureInfo]::InvariantCulture.Name)
    [int]Compare([string]$x, [string]$y) {
        return $this.CompareInfo.Compare($x, $y, [Globalization.CompareOptions]::OrdinalIgnoreCase)
    }
}

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
# You may be tempted to delete the sidecar - DO NOT DO THIS - the sidecare
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
    # Generate code for all different permutations we need.
    # All output goes to a temporary directory; the generated files are not committed.
    # LTTng files are generated at cmake configure time by the build system.
    Invoke-Expression "${ClogDir}/clog -p windows --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p windows_kernel --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p stubs --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p linux --dynamicTracepointProvider --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
    Invoke-Expression "${ClogDir}/clog -p macos --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
} finally {
    $env:DOTNET_ROLL_FORWARD = $OriginalDOTNET_ROLL_FORWARD
}

# Return to where we started
Set-Location $OrigDir
