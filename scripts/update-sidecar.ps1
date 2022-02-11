<#

.SYNOPSIS
This regenerates the CLOG sidecar file.

#>

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

$OutputDir = Join-Path $RootDir "src" "generated"

# Remove the linux directories - so that we delete files that have been abandoned
if (Test-Path $OutputDir) {

    if (Test-Path (Join-Path $OutputDir linux)) {
        Remove-Item (Join-Path $OutputDir linux) -Recurse -Force
    }
}

$Sidecar = Join-Path $SrcDir "manifest" "clog.sidecar"
$ConfigFile = Join-Path $SrcDir "manifest" "msquic.clog_config"

$TmpOutputDir = Join-Path $RootDir "build" "tmp"
$ClogDir = Join-Path $RootDir "build" "clog"

# Create directories
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $OutputDir linux) -ItemType Directory -Force | Out-Null

# Build CLOG, placing results into the CLOG directory under our build directory
dotnet publish ../submodules/clog/src/clog -o ${ClogDir} -f net6.0

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

# Generate code for all different permutations we need
Invoke-Expression "${ClogDir}/clog -p windows --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
Invoke-Expression "${ClogDir}/clog -p windows_kernel --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
Invoke-Expression "${ClogDir}/clog -p stubs --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"
Invoke-Expression "${ClogDir}/clog -p linux --dynamicTracepointProvider --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory (Join-Path $OutputDir linux) --inputFiles $allFiles"
Invoke-Expression "${ClogDir}/clog -p macos --scopePrefix quic.clog -s $Sidecar -c $ConfigFile --outputDirectory $TmpOutputDir --inputFiles $allFiles"

# Return to where we started
Set-Location $OrigDir
