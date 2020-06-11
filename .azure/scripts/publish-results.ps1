# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$GitPath = Join-Path $RootDir "artifacts/PerfDataGit"
$ResultsPath = Join-Path $RootDir "artifacts/PerfDataResult"

$env:GIT_REDIRECT_STDERR = '2>&1'
git clone https://github.com/microsoft/msquic $GitPath
$currentLoc = Get-Location
Set-Location -Path $GitPath
git checkout data/performance

Copy-Item -Path $ResultsPath -Destination $GitPath -Recurse

git status
Set-Location -Path $currentLoc
