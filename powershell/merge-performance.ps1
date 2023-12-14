<#

.SYNOPSIS
This merges performance results into a single group of built files.

.EXAMPLE
    merge-performance.ps1

.EXAMPLE
    merge-performance.ps1 -Branch /refs/heads/release/xxxx -PublishResults

#>


Using module .\mergetypes.psm1;

param (
    [Parameter(Mandatory = $false)]
    [string]$Branch = "refs/heads/main",

    [Parameter(Mandatory = $false)]
    [switch]$PublishResults = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$PotentialPR = $Env:SYSTEM_PULLREQUEST_TARGETBRANCH
if (![string]::IsNullOrWhiteSpace($PotentialPR)) {
    $BranchName = $PotentialPR;
} elseif ($Branch.StartsWith("refs/heads/")) {
    # Remove the 'refs/heads/' prefix.
    $BranchName = $Branch.Substring(11);
} else {
    # Reformat 'refs/pull/1/merge' to 'pr-1'
    $BranchName = "pr-$($Branch.Split('/')[2])"
}

Write-Host "Using branch name = '$BranchName'"

# Verify the PAT environmental variable is set.
if ($PublishResults) {
    if ($null -eq $Env:MAPPED_DEPLOYMENT_KEY -or "" -eq $Env:MAPPED_DEPLOYMENT_KEY) {
        Write-Error "PAT for GitHub Repo doesn't exist!"
    }
}

class ThroughputTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [double[]]$IndividualRunResults;
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;
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

class HPSTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [double[]]$IndividualRunResults;
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

    if ($Data.TestName -eq "Throughput") {
        $Configuration = [ThroughputConfiguration]::new();
        $Configuration.Loopback = $Data.Loopback;
        $Configuration.Encryption = $Data.Encryption;
        $Configuration.SendBuffering = $Data.SendBuffering;
        $Configuration.NumberOfStreams = $Data.NumberOfStreams;
        $Configuration.ServerToClient = $Data.ServerToClient;
        $Model.TputConfig = $Configuration;
    } elseif ($Data.TestName -eq "TcpThroughput") {
        $Configuration = [ThroughputConfiguration]::new();
        $Configuration.Loopback = $Data.Loopback;
        $Configuration.Encryption = $Data.Encryption;
        $Configuration.SendBuffering = $Data.SendBuffering;
        $Configuration.NumberOfStreams = $Data.NumberOfStreams;
        $Configuration.ServerToClient = $Data.ServerToClient;
        $Model.TputConfig = $Configuration;
    } elseif ($Data.TestName -eq "RPS") {
        $Configuration = [RpsConfiguration]::new();
        $Configuration.ConnectionCount = $Data.ConnectionCount;
        $Configuration.RequestSize = $Data.RequestSize;
        $Configuration.ResponseSize = $Data.ResponseSize;
        $Configuration.ParallelRequests = $Data.ParallelRequests;
        $Model.RpsConfig = $Configuration;
    } elseif ($Data.TestName -eq "TcpRPS") {
        $Configuration = [RpsConfiguration]::new();
        $Configuration.ConnectionCount = $Data.ConnectionCount;
        $Configuration.RequestSize = $Data.RequestSize;
        $Configuration.ResponseSize = $Data.ResponseSize;
        $Configuration.ParallelRequests = $Data.ParallelRequests;
        $Model.RpsConfig = $Configuration;
    } elseif ($Data.TestName -eq "HPS") {
        $Configuration = [HpsConfiguration]::new();
        $Model.HpsConfig = $Configuration;
    } elseif ($Data.TestName -eq "TcpHPS") {
        $Configuration = [HpsConfiguration]::new();
        $Model.HpsConfig = $Configuration;
    } else {
        Write-Error "Unknown Test Name $Data"
    }

    $CommitModel.Tests.Add($Model)
}

$CpuLimitedData = $CommitModel | ConvertTo-Json -Depth 100

$BranchFolder = Join-Path $RootDir 'data' $BranchName
$CommitFolder = Join-Path $BranchFolder $CommitModel.CommitHash
New-Item -Path $CommitFolder -ItemType "directory" -Force | Out-Null
$DataFileName = Join-Path $CommitFolder "cpu_data.json"
Out-File -FilePath $DataFileName -InputObject $CpuLimitedData -Force

$CommitsFile = Join-Path $BranchFolder "commits.json"
$NewCommit = [CommitsFileModel]::new();
$NewCommit.CommitHash = $CommitModel.CommitHash;
$NewCommit.Date = $CommitModel.Date;
$NewCommitsContents = $null
if (Test-Path -Path $CommitsFile -PathType Leaf) {
    $CommitsContents = Get-Content $CommitsFile | ConvertFrom-Json -NoEnumerate
    $NewCommit = [CommitsFileModel]::new();
    $NewCommit.CommitHash = $CommitModel.CommitHash;
    $NewCommit.Date = $CommitModel.Date;
    $CommitsContents += $NewCommit;
    $NewCommitsContents = $CommitsContents | Sort-Object -Property CommitHash -Unique | Sort-Object -Property Date -Descending -Unique | ConvertTo-Json -AsArray

} else {
    $CommitsArr = @($NewCommit)
    $NewCommitsContents = $CommitsArr | ConvertTo-Json -AsArray
}
Out-File -FilePath $CommitsFile -InputObject $NewCommitsContents -Force

$HistogramOutDir = Join-Path $CommitFolder "RpsLatency"
New-Item -Path $HistogramOutDir -ItemType "directory" -Force | Out-Null
Write-Debug "Copying histogram files to $HistogramOutDir"

$HistogramFilesPaths = Join-Path $RootDir "artifacts/PerfDataResults/performance/*.txt"
$HistogramFiles = Get-ChildItem -Path $HistogramFilesPaths -Recurse -File -Exclude *Log*
Write-Debug "Found $($HistogramFiles.Length) files"
#Write-Debug $HistogramFiles
$HistogramFiles | Copy-Item -Destination $HistogramOutDir

$GraphScript = Join-Path $PSScriptRoot generate-graphs.ps1

& $GraphScript -BranchName $BranchName

# Copy entire commit folder to outputs
$OutputFolder = Join-Path $RootDir "artifacts" "mergedPerfResults"
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
Copy-Item -Recurse -Path "$CommitFolder\*" $OutputFolder -Force

$env:GIT_REDIRECT_STDERR = '2>&1'
Set-Location $RootDir

if ($PublishResults) {

    git config --global credential.helper store
    Set-Content -Path "$env:HOME\.git-credentials" -Value "https://$($env:MAPPED_DEPLOYMENT_KEY):x-oauth-basic@github.com`n" -NoNewLine

    # Set Git Config Info
    git config user.email "quicdev@microsoft.com"
    git config user.name "QUIC Dev[bot]"

    $CommitHash = $CommitModel.CommitHash

    git add .
    git status
    git commit -m "Commit Test Results for $CommitHash"
    git pull
    git push
} else {
    git add .
    git status
}
