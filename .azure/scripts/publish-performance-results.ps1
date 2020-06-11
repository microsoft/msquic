# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$RootDir = Split-Path $RootDir -Parent

$GitPath = Join-Path $RootDir "artifacts/PerfDataGit"
$ResultsPath = Join-Path $RootDir "artifacts/PerfDataResults/*"

$env:GIT_REDIRECT_STDERR = '2>&1'
git clone  --single-branch --branch data/performance https://github.com/microsoft/msquic $GitPath
$currentLoc = Get-Location
Set-Location -Path $GitPath

Copy-Item -Path $ResultsPath -Destination $GitPath -Recurse -Force
git add .
git status
Set-Location -Path $currentLoc
