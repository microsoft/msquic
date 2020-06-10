
Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$RootDir = Split-Path $PSScriptRoot -Parent
$GitPath = Join-Path $RootDir "build/PerfData"

function Clone-Data-Repo() {
    git clone https://github.com/microsoft/msquic $GitPath
    $currentLoc = Get-Location
    Set-Location -Path $GitPath
    git clean -d -x -f
    git reset --hard
    git checkout data/performance
    git pull
    Set-Location -Path $currentLoc
}

Clone-Data-Repo

function Get-Latest-Result($Path) {
    $FullLatestResult = Get-Item -Path $Path | Get-Content -Tail 1
    $SplitLatestResult =  $FullLatestResult -split ','
    $LatestResult = $SplitLatestResult[$SplitLatestResult.Length - 1].Trim()
    return $LatestResult
}

$WindowsLoopbackPath = Join-Path $GitPath "windows/loopback/results.csv"
$LoopbackResult = Get-Latest-Result -Path $WindowsLoopbackPath
Write-Host $LoopbackResult
