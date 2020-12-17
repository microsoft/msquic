<#

.SYNOPSIS
This takes merged performance results and generates graphs to display.
This is ran from merge-performance.ps1

#>

Using module .\mergetypes.psm1

param (
    [Parameter(Mandatory = $true)]
    [string]$BranchFolder,

    [Parameter(Mandatory = $false)]
    [int]$DaysToReceive = 30
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

function Get-CommitTimePairJs {
    param (
        [Parameter(Mandatory = $true)]
        [CommitsFileModel[]]$CommitModel
    )

    $DataVal = ""
    foreach ($Pair in $CommitModel) {
        $TimeUnix = ([DateTimeOffset]$Pair.Date).ToUnixTimeMilliseconds();
        $Hash = $Pair.CommitHash
        $Data = "'$TimeUnix': '$Hash'"
        if ($DataVal -eq "") {
            $DataVal = $Data
        } else {
            $DataVal = "$DataVal, $Data"
        }
    }
    return "{$DataVal}"
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
            $Data = "{t: new Date($TimeUnix), rawTime: $TimeUnix, y: $Result}"
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
        $Data = "{t: new Date($TimeUnix), rawTime: $TimeUnix, y: $Average}"
        if ($DataVal -eq "") {
            $DataVal = $Data
        } else {
            $DataVal = "$DataVal, $Data"
        }
    }
    return "[$DataVal]"
}

#region THROUGHPUT

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

function Get-ThroughputPlatformTests {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[ThroughputTest]]$ThroughputTests,

        [Parameter(Mandatory = $true)]
        [string]$RawReplaceName,

        [Parameter(Mandatory = $true)]
        [string]$AvgReplaceName
    )

    $RawData = Get-RawTestDataJs -TestList $ThroughputTests
    $AvgData = Get-AverageDataJs -TestList $ThroughputTests

    $DataFile = $DataFile.Replace($RawReplaceName, $RawData)
    $DataFile = $DataFile.Replace($AvgReplaceName, $AvgData)

    return $DataFile
}

function Get-ThroughputTestsJs {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$CpuCommitData
    )

    # Dict<Config, Dict<Platform, List<Tests>>>
    $ThroughputTests = Get-ThroughputTests -CommitData $CpuCommitData
    
    $UploadDefault = Get-ThroughputDefault -Download $false

    $DownloadDefault = Get-ThroughputDefault -Download $true

    $UploadTests = $ThroughputTests[$UploadDefault];
    $DownloadTests = $ThroughputTests[$DownloadDefault];

    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_UP" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_UP"
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_UP" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_UP"
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_UP" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_UP"

    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_DOWN" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_DOWN"
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_DOWN" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_DOWN"
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_DOWN" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_DOWN"

    return $DataFile
}

#endregion

#region RPS

function Get-RPSDefault {
    [OutputType([RpsConfiguration])]
    param (
    )
    $RpsConfig = [RpsConfiguration]::new();
    $RpsConfig.ConnectionCount = 250;
    $RpsConfig.ParallelRequests = 30;
    $RpsConfig.RequestSize = 0;
    $RpsConfig.ResponseSize = 4096;
    return $RpsConfig
}

class RpsTest {
    [string]$CommitHash;
    [datetime]$Date;
    [string]$MachineName;
    [double[]]$Results;
}

function Get-RpsTests {
    [OutputType([Collections.Generic.Dictionary[RpsConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[RpsTest]]   ]])]
    param (
        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$CommitData
    )
    $Tests = [Collections.Generic.Dictionary[RpsConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[RpsTest]]   ]]::new()

    foreach ($CommitModel in $CommitData) {
        foreach ($Test in $CommitModel.Tests) {
            if ($null -eq $Test.RpsConfig) {
                continue
            }
            if ($Tests.ContainsKey($Test.RpsConfig)) {
                $TestDict = $Tests[$Test.RpsConfig];
            } else {
                $TestDict = [Collections.Generic.Dictionary[string, Collections.Generic.List[RpsTest]]]::new();
                $Tests.Add($Test.RpsConfig, $TestDict)
            }
            $NewTest = [RpsTest]::new();
            $NewTest.CommitHash = $CommitModel.CommitHash
            $NewTest.Date = $CommitModel.Date;
            $NewTest.MachineName = $Test.MachineName;
            $NewTest.Results = $Test.Results;

            if ($TestDict.ContainsKey($Test.PlatformName)) {
                $PlatformList = $TestDict[$Test.PlatformName]
            } else {
                $PlatformList = [ Collections.Generic.List[RpsTest]]::new()
                $TestDict.Add($Test.PlatformName, $PlatformList)
            }

            $PlatformList.Add($NewTest);
        }
    }

    return $Tests
}

function Get-RpsPlatformTests {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[RpsTest]]$RpsTests,

        [Parameter(Mandatory = $true)]
        [string]$RawReplaceName,

        [Parameter(Mandatory = $true)]
        [string]$AvgReplaceName
    )

    $RawData = Get-RawTestDataJs -TestList $RpsTests
    $AvgData = Get-AverageDataJs -TestList $RpsTests

    $DataFile = $DataFile.Replace($RawReplaceName, $RawData)
    $DataFile = $DataFile.Replace($AvgReplaceName, $AvgData)

    return $DataFile
}

function Get-RpsTestsJs {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$CpuCommitData
    )

    # Dict<Config, Dict<Platform, List<Tests>>>
    $RpsTests = Get-RpsTests -CommitData $CpuCommitData
    
    $RpsDefault = Get-RpsDefault;

    $RpsTestConfig = $RpsTests[$RpsDefault];

    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_RPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_RPS"
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_RPS" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_RPS"
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_RPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_RPS"

    return $DataFile
}

#endregion

#region HPS

function Get-HPSDefault {
    [OutputType([HpsConfiguration])]
    param (
    )
    $RpsConfig = [HpsConfiguration]::new();
    return $RpsConfig
}

class HpsTest {
    [string]$CommitHash;
    [datetime]$Date;
    [string]$MachineName;
    [double[]]$Results;
}

function Get-HpsTests {
    [OutputType([Collections.Generic.Dictionary[HpsConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[HpsTest]]   ]])]
    param (
        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$CommitData
    )
    $Tests = [Collections.Generic.Dictionary[HpsConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[HpsTest]]   ]]::new()

    foreach ($CommitModel in $CommitData) {
        foreach ($Test in $CommitModel.Tests) {
            if ($null -eq $Test.HpsConfig) {
                continue
            }
            if ($Tests.ContainsKey($Test.HpsConfig)) {
                $TestDict = $Tests[$Test.HpsConfig];
            } else {
                $TestDict = [Collections.Generic.Dictionary[string, Collections.Generic.List[HpsTest]]]::new();
                $Tests.Add($Test.HpsConfig, $TestDict)
            }
            $NewTest = [HpsTest]::new();
            $NewTest.CommitHash = $CommitModel.CommitHash
            $NewTest.Date = $CommitModel.Date;
            $NewTest.MachineName = $Test.MachineName;
            $NewTest.Results = $Test.Results;

            if ($TestDict.ContainsKey($Test.PlatformName)) {
                $PlatformList = $TestDict[$Test.PlatformName]
            } else {
                $PlatformList = [ Collections.Generic.List[HpsTest]]::new()
                $TestDict.Add($Test.PlatformName, $PlatformList)
            }

            $PlatformList.Add($NewTest);
        }
    }

    return $Tests
}

function Get-HpsPlatformTests {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[HpsTest]]$HpsTests,

        [Parameter(Mandatory = $true)]
        [string]$RawReplaceName,

        [Parameter(Mandatory = $true)]
        [string]$AvgReplaceName
    )

    $RawData = Get-RawTestDataJs -TestList $HpsTests
    $AvgData = Get-AverageDataJs -TestList $HpsTests

    $DataFile = $DataFile.Replace($RawReplaceName, $RawData)
    $DataFile = $DataFile.Replace($AvgReplaceName, $AvgData)

    return $DataFile
}

function Get-HpsTestsJs {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$CpuCommitData
    )

    # Dict<Config, Dict<Platform, List<Tests>>>
    $HpsTests = Get-HpsTests -CommitData $CpuCommitData
    
    $HpsDefault = Get-HpsDefault;

    $HpsTestConfig = $HpsTests[$HpsDefault];

    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_HPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_HPS"
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_HPS" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_HPS"
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_HPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_HPS"

    return $DataFile
}

#endregion

$CommitHistory = Get-CommitHistory -DaysToReceive $DaysToReceive -BranchFolder $BranchFolder
$CpuCommitData = Get-CpuCommitData -CommitHistory $CommitHistory -BranchFolder $BranchFolder

$DataFileIn = Join-Path $PSScriptRoot "data.js.in"
$DataFileContents = Get-Content $DataFileIn

$FirstAndLast = $CommitHistory | Sort-Object -Property Date | Select-Object -Index 0, ($CommitHistory.Count - 1)

$NewestDateString = ([DateTimeOffset]$FirstAndLast[1].Date).ToUnixTimeMilliseconds()
$OldestDateString = ([DateTimeOffset]$FirstAndLast[0].Date).ToUnixTimeMilliseconds()

$DataFileContents = $DataFileContents.Replace("NEWEST_DATE", "new Date($NewestDateString)")
$DataFileContents = $DataFileContents.Replace("OLDEST_DATE", "new Date($OldestDateString)")

$DataFileContents = $DataFileContents.Replace("COMMIT_DATE_PAIR", (Get-CommitTimePairJs -CommitModel $CommitHistory))

$DataFileContents = Get-ThroughputTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData
$DataFileContents = Get-RpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData
$DataFileContents = Get-HpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData

$DataFileOut = Join-Path $PSScriptRoot "data.js"
$DataFileContents | Set-Content $DataFileOut
