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


foreach ($File in $Files) {
    $Data = Get-Content $File | ConvertFrom-Json;

    if ($null -eq $CommitModel.CommitHash) {
        $CommitModel.CommitHash = $Data.CommitHash;
        $CommitModel.Date = Get-Date
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

$Formatted = $CommitModel | ConvertTo-Json -Depth 100

$BranchName = 'main' # chosen by random dice roll

$CommitFolder = Join-Path $RootDir 'data' $BranchName $CommitModel.CommitHash
New-Item -Path $CommitFolder -ItemType "directory" -Force
$DataFileName = Join-Path $CommitFolder "cpu_data.json"
Out-File -FilePath $DataFileName -InputObject $Formatted -Force
