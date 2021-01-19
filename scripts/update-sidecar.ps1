<#

.SYNOPSIS
This updates/regenerates the CLOG sidecar file.

.PARAMETER Clean
    Deletes the old sidecar file first.

#>

param (
    [Parameter(Mandatory = $false)]
    [switch]$Clean = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

class SimpleStringComparer:Collections.Generic.IComparer[string] {
    [Globalization.CompareInfo]$CompareInfo = [Globalization.CompareInfo]::GetCompareInfo([CultureInfo]::InvariantCulture.Name)
    [int]Compare([string]$x, [string]$y) {
        return $this.CompareInfo.Compare($x, $y, [Globalization.CompareOptions]::OrdinalIgnoreCase)
    }
}

$RootDir = Split-Path $PSScriptRoot -Parent
$SrcDir = Join-Path $RootDir "src"

$Files = [System.Collections.Generic.List[string]](Get-ChildItem -Path "$SrcDir\*" -Recurse -Include *.c,*.h,*.cpp,*.hpp -File)
$Files.Sort([SimpleStringComparer]::new())

$Sidecar = Join-Path $SrcDir "manifest" "clog.sidecar"
$ConfigFile = Join-Path $SrcDir "manifest" "msquic.clog_config"

$OutputDir = Join-Path $RootDir "build" "tmp"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

if ($Clean) {
    Remove-Item $Sidecar -Force -ErrorAction Ignore | Out-Null
}

foreach ($File in $Files) {
    clog -p windows --scopePrefix "QUIC" -s $Sidecar -c $ConfigFile -i $File --outputDirectory "$OutputDir"
    clog -p windows_kernel --scopePrefix "QUIC" -s $Sidecar -c $ConfigFile -i $File --outputDirectory "$OutputDir"
    clog -p stubs --scopePrefix "QUIC" -s $Sidecar -c $ConfigFile -i $File --outputDirectory "$OutputDir"
    clog -p linux --scopePrefix "QUIC" -s $Sidecar -c $ConfigFile -i $File --outputDirectory "$OutputDir"
}
