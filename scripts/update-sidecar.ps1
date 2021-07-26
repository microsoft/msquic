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
$RootDir = Split-Path $PSScriptRoot -Parent
$SrcDir = Join-Path $RootDir "src"

$OutputDir = Join-Path $RootDir "src" "generated"
if (Test-Path $OutputDir) {
    Remove-Item $OutputDir -Recurse -Force -Exclude 'CMakeLists.txt'
}

$Files = [System.Collections.Generic.List[string]](Get-ChildItem -Path "$SrcDir\*" -Recurse -Include *.c,*.h,*.cpp,*.hpp -File)
$Files.Sort([SimpleStringComparer]::new())

$Sidecar = Join-Path $SrcDir "manifest" "clog.sidecar"
$ConfigFile = Join-Path $SrcDir "manifest" "msquic.clog_config"

$TmpOutputDir = Join-Path $RootDir "build" "tmp"

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Remove-Item $Sidecar -Force -ErrorAction Ignore | Out-Null

clog --installDirectory (Join-Path $OutputDir common)

foreach ($File in $Files) {
    $FileToCheck = [System.IO.Path]::GetFileName($File) + ".clog.h"
    $FileContents = (Get-Content -path $File -Raw)
    if ($null -eq $FileContents -or  !$FileContents.Contains($FileToCheck)) {
        continue
    }
    clog -p windows --dynamicTracepointProvider --scopePrefix "quic.clog" -s $Sidecar -c $ConfigFile -i $File --outputDirectory $TmpOutputDir
    clog -p windows_kernel --dynamicTracepointProvider --scopePrefix "quic.clog" -s $Sidecar -c $ConfigFile -i $File --outputDirectory $TmpOutputDir
    clog -p stubs --dynamicTracepointProvider --scopePrefix "quic.clog" -s $Sidecar -c $ConfigFile -i $File --outputDirectory $TmpOutputDir
    clog -p linux --dynamicTracepointProvider --scopePrefix "quic.clog" -s $Sidecar -c $ConfigFile -i $File --outputDirectory (Join-Path $OutputDir linux)
    clog -p macos --dynamicTracepointProvider --scopePrefix "quic.clog" -s $Sidecar -c $ConfigFile -i $File --outputDirectory $TmpOutputDir
}

# Perform fixups
$GenFiles = Get-ChildItem -Path "$OutputDir\*" -Recurse -File
$ToRemovePath = "$OutputDir\linux\"
foreach ($File in $GenFiles) {
    ((Get-Content -path $File -Raw).Replace($ToRemovePath, "")) | Set-Content -Path $File -NoNewline
}
foreach ($File in $GenFiles) {
    $Content = Get-Content -path $File | Where-Object {$_ -notmatch "// CLOG generated "}
    $Content | Set-Content -Path $File
}
foreach ($File in $GenFiles) {
    $Content = Get-Content -path $File | Where-Object {$_ -notmatch "// CLOG generated "}
    $Content | Set-Content -Path $File
}
