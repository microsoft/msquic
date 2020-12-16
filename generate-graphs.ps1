<#

.SYNOPSIS
This takes merged performance results and generates graphs to display. 
This is ran from merge-performance.ps1

#>

Using module .\mergetypes.psm1

param (
    [Parameter(Mandatory = $true)]
    [TestCommitModel]$Model,

    [Parameter(Mandatory = $true)]
    [string]$CommitFolder,

    [Parameter(Mandatory = $true)]
    [string]$BranchFolder
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Get-CommitHistory {
    [OutputType([CommitsFileModel[]])]
    param (
        [Parameter(Mandatory = $true)]
        [int]$DaysToReceive,

        [Parameter(Mandatory = $true)]
        [string]$BranchFolder
    )

    $CurrentDate = Get-Date
    $PastDate = $CurrentDate.AddDays(-$DaysToReceive)
    
    $CommitsFile = Join-Path $BranchFolder "commits.json"
    $CommitsContents = Get-Content $CommitsFile | ConvertFrom-Json | Where-Object -Property Date -GE $PastDate

    return $CommitsContents
}

function Get-CpuCommitData {
    [OutputType([TestCommitModel[]])]
    param (
        [Parameter(Mandatory = $true)]
        [CommitsFileModel[]]$CommitHistory,

        [Parameter(Mandatory = $true)]
        [string]$BranchFolder
    )

    $CpuData = @()

    foreach ($SingleCommitHis in $CommitHistory) {
        $CommitDataFile = Join-Path $BranchFolder $SingleCommitHis.CommitHash "cpu_data.json"
        $CpuData += Get-Content $CommitDataFile | ConvertFrom-Json
    }
    return $CpuData
}

function Get-ThroughputDefault {
    [OutputType([ThroughputConfiguration])]
    param (
        [Parameter(Mandatory = $true)]
        [boolean]$Download
    )
    $TputConfig = [ThroughputConfiguration]::new();
    $TputConfig.Encryption = $true;
    $TputConfig.Loopback = $false;
    $TputConfig.NumberOfStreams = 1;
    $TputConfig.SendBuffering = $false;
    $TputConfig.ServerToClient = $Download
    return $TputConfig
}

class ThroughputTest {
    [string]$CommitHash;
    [datetime]$Date;
    [string]$MachineName;
    [double[]]$Results;
}

function Get-ThroughputTests {
    [OutputType([Collections.Generic.Dictionary[ThroughputConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[ThroughputTest]]   ]])]
    param (
        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$CommitData
    )
    $Tests = [Collections.Generic.Dictionary[ThroughputConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[ThroughputTest]]   ]]::new()

    foreach ($CommitModel in $CommitData) {
        foreach ($Test in $CommitModel.Tests) {
            if ($null -eq $Test.TputConfig) {
                continue
            }
            if ($Tests.ContainsKey($Test.TputConfig)) {
                $TestDict = $Tests[$Test.TputConfig];
            } else {
                $TestDict = [Collections.Generic.Dictionary[string, Collections.Generic.List[ThroughputTest]]]::new();
                $Tests.Add($Test.TputConfig, $TestDict)
            }
            $NewTest = [ThroughputTest]::new();
            $NewTest.CommitHash = $CommitModel.CommitHash
            $NewTest.Date = $CommitModel.Date;
            $NewTest.MachineName = $Test.MachineName;
            $NewTest.Results = $Test.Results;

            if ($TestDict.ContainsKey($Test.PlatformName)) {
                $PlatformList = $TestDict[$Test.PlatformName]
            } else {
                $PlatformList = [ Collections.Generic.List[ThroughputTest]]::new()
                $TestDict.Add($Test.PlatformName, $PlatformList)
            }

            $PlatformList.Add($NewTest);
        }
    }

    return $Tests
}

function Get-LabelsJs {
    param (
        [Parameter(Mandatory = $true)]
        [CommitsFileModel[]]$CommitList
    )

    $LabelVal = ""
    foreach ($Commit in $CommitList) {
        $TimeUnix = ([DateTimeOffset]$Commit.Date).ToUnixTimeMilliseconds();
        $Label = "new Date($TimeUnix)"
        if ($LabelVal -eq "") {
            $LabelVal = $Label
        } else {
            $LabelVal = "$LabelVal, $Label"
        }
    }
    return "[$LabelVal]"
}

function Get-RawTestDataJs {
    param (
        [Parameter(Mandatory = $true)]
        $TestList
    )
    
    $DataVal = ""
    foreach ($Test in $TestList) {
        $TimeUnix = ([DateTimeOffset]$Test.Date).ToUnixTimeMilliseconds();
        foreach ($Result in $Test.Results) {
            $Data = "{t: new Date($TimeUnix), y: $Result}"
            if ($DataVal -eq "") {
                $DataVal = $Data
            } else {
                $DataVal = "$DataVal, $Data"
            }
        }
    }
    return "[$DataVal]"
}

function Get-AverageDataJs {
    param (
        [Parameter(Mandatory = $true)]
        $TestList
    )
    
    $DataVal = ""
    foreach ($Test in $TestList) {
        $TimeUnix = ([DateTimeOffset]$Test.Date).ToUnixTimeMilliseconds();
        $Average = ($Test.Results  | Measure-Object -Average).Average
        $Data = "{t: new Date($TimeUnix), y: $Average}"
        if ($DataVal -eq "") {
            $DataVal = $Data
        } else {
            $DataVal = "$DataVal, $Data"
        }
    }
    return "[$DataVal]"
}

# Do Stuff Here
$CommitHistory = Get-CommitHistory -DaysToReceive 14 -BranchFolder $BranchFolder
$CpuCommitData = Get-CpuCommitData -CommitHistory $CommitHistory -BranchFolder $BranchFolder

$DataLabels = Get-LabelsJs -CommitList $CommitHistory

$ThroughputTests = Get-ThroughputTests -CommitData $CpuCommitData

$UploadDefault = Get-ThroughputDefault -Download $false

$DefaultThroughputUploadTests = $ThroughputTests[$UploadDefault];

$KernelModeTests = $DefaultThroughputUploadTests["Winkernel_x64_schannel"]

$KmRawData = Get-RawTestDataJs -TestList $KernelModeTests
$KmAverageData = Get-AverageDataJs -TestList $KernelModeTests

$DataFileIn = Join-Path $PSScriptRoot "data.js.in"
$DataFileContents = Get-Content $DataFileIn

$DataFileContents = $DataFileContents.Replace("RAW_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT", $KmRawData)
$DataFileContents = $DataFileContents.Replace("AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT", $KmAverageData)
$DataFileContents = $DataFileContents.Replace("DATA_LABELS", $DataLabels)

$DataFileOut = Join-Path $PSScriptRoot "data.js"
$DataFileContents | Set-Content $DataFileOut

# $A = [ThroughputConfiguration]::new()
# $B = [ThroughputConfiguration]::new()

# $Dictionary = [Collections.Generic.Dictionary[ThroughputConfiguration, string]]::new()
# $Dictionary.Add($A, "42")
# $Dictionary.Add($B, "42")

# Write-Host $Dictionary.Count


#Write-Host $CpuCommitData
