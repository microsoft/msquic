Using module .\mergetypes.psm1;

param (
    [Parameter(Mandatory = $false)]
    [string]$Branch = "refs/heads/main",

    [Parameter(Mandatory = $false)]
    [switch]$PublishResults = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if ($Branch.StartsWith("refs/heads/")) {
    # Remove the 'refs/heads/' prefix.
    $BranchName = $Branch.Substring(11);
} else {
    Write-Error "Unsupported Branch Name"
}

Write-Host "Using branch name = '$BranchName'"

# Verify the PAT environmental variable is set.
if ($PublishResults) {
    if ($null -eq $Env:MAPPED_DEPLOYMENT_KEY -or "" -eq $Env:MAPPED_DEPLOYMENT_KEY) {
        Write-Error "PAT for GitHub Repo doesn't exist!"
    }
}

class RPSTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [double[]]$IndividualRunResults;
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$ResultsPath = Join-Path $RootDir "artifacts/PerfDataResults/*.json"

# Enumerate files
$Files = Get-ChildItem -Path $ResultsPath -Recurse -File;

$CommitModel = [TestCommitModel]::new()
$CommitModel.Tests = New-Object Collections.Generic.List[TestModel]

foreach ($File in $Files) {
    $Data = Get-Content $File | ConvertFrom-Json;

    if ($null -eq $CommitModel.CommitHash) {
        $CommitModel.CommitHash = $Data.CommitHash;
        $CommitModel.Date = $Data.AuthKey # Change when we can rename this field after DB removal
    } elseif ($CommitModel.CommitHash -ne $Data.CommitHash) {
        Write-Error "Mismatched commit hashes"
    }

    $Model = [TestModel]::new();
    $Model.MachineName = $Data.MachineName;
    $Model.PlatformName = $Data.PlatformName;
    $Model.TestName = $Data.TestName;
    $Model.Results = $Data.IndividualRunResults;

    if ($Data.TestName -eq "RPS") {
        $Configuration = [RpsConfiguration]::new();
        $Configuration.ConnectionCount = $Data.ConnectionCount;
        $Configuration.RequestSize = $Data.RequestSize;
        $Configuration.ResponseSize = $Data.ResponseSize;
        $Configuration.ParallelRequests = $Data.ParallelRequests;
        $Model.RpsConfig = $Configuration;
    } else {
        Write-Error "Unknown Test Name ${$Data.TestName}"
    }

    $CommitModel.Tests.Add($Model)
}

$PeriodicRpsData = $CommitModel | ConvertTo-Json -Depth 100

$RunDate = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

$BranchFolder = Join-Path $RootDir 'periodic' $BranchName
$CommitFolder = Join-Path $BranchFolder $RunDate
New-Item -Path $CommitFolder -ItemType "directory" -Force | Out-Null
$DataFileName = Join-Path $CommitFolder "rps_data.json"
Out-File -FilePath $DataFileName -InputObject $PeriodicRpsData -Force

$CommitsFile = Join-Path $BranchFolder "commits.json"
$NewCommit = [CommitsFileModel]::new();
$NewCommit.CommitHash = $CommitModel.CommitHash;
$NewCommit.Date = $RunDate;
$NewCommitsContents = $null
if (Test-Path -Path $CommitsFile -PathType Leaf) {
    $CommitsContents = Get-Content $CommitsFile | ConvertFrom-Json -NoEnumerate
    $NewCommit = [CommitsFileModel]::new();
    $NewCommit.CommitHash = $CommitModel.CommitHash;
    $NewCommit.Date = $RunDate;
    $CommitsContents += $NewCommit;
    $NewCommitsContents = $CommitsContents | Sort-Object -Property Date -Descending -Unique | ConvertTo-Json -AsArray

} else {
    $CommitsArr = @($NewCommit)
    $NewCommitsContents = $CommitsArr | ConvertTo-Json -AsArray
}
Out-File -FilePath $CommitsFile -InputObject $NewCommitsContents -Force

$HistogramFilesPaths = Join-Path $RootDir "artifacts/PerfDataResults/histogram*.txt"
$HistogramFiles = Get-ChildItem -Path $HistogramFilesPaths -Recurse -File;
$HistogramDir = Join-Path $CommitFolder "RpsLatency"
New-Item -Path $HistogramDir -ItemType "directory" -Force | Out-Null
$HistogramFiles | Copy-Item -Destination $HistogramDir

$GraphScript = Join-Path $PSScriptRoot generate-periodic-graphs.ps1

& $GraphScript -BranchName $BranchName

# Copy entire commit folder to outputs
$OutputFolder = Join-Path $RootDir "artifacts" "mergedPerfResults"
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
Copy-Item -Recurse -Path "$CommitFolder\*" $OutputFolder -Force

# Copy per commit webpage as well
$OutputFolder = Join-Path $OutputFolder "percommitpage"
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
$CommitFolder = Join-Path $RootDir "percommit" $BranchName $CommitModel.CommitHash
Copy-Item -Recurse -Path "$CommitFolder\*" $OutputFolder -Force

$env:GIT_REDIRECT_STDERR = '2>&1'
Set-Location $RootDir

if ($PublishResults) {

    git config --global credential.helper store
    Set-Content -Path "$env:HOME\.git-credentials" -Value "https://$($env:MAPPED_DEPLOYMENT_KEY):x-oauth-basic@github.com`n" -NoNewLine

    # Set Git Config Info
    git config user.email "quicdev@microsoft.com"
    git config user.name "QUIC Dev Bot"

    $CommitHash = $CommitModel.CommitHash

    git add .
    git status
    git commit -m "Commit Test Results for $CommitHash"
    git pull
    git push
} else {
    #git add .
    #git status
}

