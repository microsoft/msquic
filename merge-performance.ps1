Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

class ThroughputConfiguration {
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;
}

class HpsConfiguration {

}

class RpsConfiguration {
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;
}

class TestModel {
    [string]$PlatformName;
    [string]$TestName;
    [string]$MachineName;
    [ThroughputConfiguration]$TputConfig;
    [RpsConfiguration]$RpsConfig;
    [HpsConfiguration]$HpsConfig;
    [double[]]$Results;
}

class TestCommitModel {
    [string]$CommitHash;
    [datetime]$Date;
    [Collections.Generic.List[TestModel]]$Tests;
}

class CommitsFileModel {
    [string]$CommitHash;
    [datetime]$Date;
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
$RootDir = $PSScriptRoot 
$ResultsPath = Join-Path $RootDir "artifacts/PerfDataResults/*.json"

# Enumerate files
$Files = Get-ChildItem -Path $ResultsPath -Recurse -File;

$CommitModel = [TestCommitModel]::new()
$CommitModel.Tests = New-Object Collections.Generic.List[TestModel]
$BranchName = ""

foreach ($File in $Files) {
    $Data = Get-Content $File | ConvertFrom-Json;

    if ($null -eq $CommitModel.CommitHash) {
        $CommitModel.CommitHash = $Data.CommitHash;
        $CommitModel.Date = Get-Date
    } elseif ($CommitModel.CommitHash -ne $Data.CommitHash) {
        Write-Error "Mismatched commit hashes"
    }

    if ($null -eq $BranchName) {
        $BranchName = $Data.AuthKey
    } elseif ($BranchName -ne $Data.AuthKey) {
        Write-Error "Mismatched branch names"
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
    } elseif ($Data.TestName -eq "RPS") {
        $Configuration = [RpsConfiguration]::new();
        $Configuration.ConnectionCount = $Data.ConnectionCount;
        $Configuration.RequestSize = $Data.RequestSize;
        $Configuration.ResponseSize = $Data.ResponseSize;
        $Configuration.ParallelRequests = $Data.ParallelRequests;
        $Model.RpsConfig = $Configuration;
    } elseif ($Data.TestName -eq "HPS") {
        $Configuration = [HpsConfiguration]::new();
        $Model.HpsConfig = $Configuration;
    } else {
        Write-Error "Unknown Test Name ${$Data.TestName}"
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
$CommitsContents = Get-Content $CommitsFile | ConvertFrom-Json
$NewCommit = [CommitsFileModel]::new();
$NewCommit.CommitHash = $CommitModel.CommitHash;
$NewCommit.Date = $CommitModel.Date;
$CommitsContents += $NewCommit;
$NewCommitsContents = $CommitsContents | Sort-Object -Property CommitHash -Unique | Sort-Object -Property Date -Descending -Unique | ConvertTo-Json
Out-File -FilePath $CommitsFile -InputObject $NewCommitsContents -Force

# Copy entire commit folder to outputs
$OutputFolder = Join-Path $RootDir "artifacts" "mergedPerfResults"
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
Copy-Item -Recurse -Path "$CommitFolder\*" $OutputFolder