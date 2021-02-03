<#

.SYNOPSIS
This takes merged performance results and generates graphs to display.
This is ran from merge-performance.ps1

#>

Using module .\mergetypes.psm1

param (
    [Parameter(Mandatory = $true)]
    [string]$BranchName,

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
        [string]$BranchFolder,

        [Parameter(Mandatory = $true)]
        [int]$MinimumCommits,

        [Parameter(Mandatory = $true)]
        [int]$MaximumCommits
    )

    $CurrentDate = Get-Date
    $PastDate = $CurrentDate.AddDays(-$DaysToReceive)
    $PastDateUnix = ([DateTimeOffset]$PastDate).ToUnixTimeMilliseconds()

    $CommitsFile = Join-Path $BranchFolder "commits.json"
    $CommitJson = Get-Content $CommitsFile | ConvertFrom-Json

    if ($MaximumCommits -ne 0) {
        # We're explicitly looking for a maximum
        if ($CommitJson.Count -lt $MaximumCommits) {
            $MaximumCommits = $CommitJson.Count
        }
        return $CommitJson | Select-Object -First $MaximumCommits
    }

    $CommitsContents = $CommitJson | Where-Object -Property Date -GE $PastDateUnix

    if ($CommitsContents.Count -lt $MinimumCommits) {
        if ($CommitJson.Count -lt $MinimumCommits) {
            $MinimumCommits = $CommitJson.Count
        }
        $CommitsContents = $CommitJson | Select-Object -First $MinimumCommits
    }

    return $CommitsContents
}

function Get-LatestCommit {
    [OutputType([CommitsFileModel[]])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$BranchFolder
    )

    $CommitsFile = Join-Path $BranchFolder "commits.json"
    $CommitsContents = Get-Content $CommitsFile | ConvertFrom-Json | Select-Object -First 1

    return $CommitsContents[0]
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
        $TimeUnix = $Pair.Date;
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
        $TestList,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    $DataVal = "";
    foreach ($Test in $TestList) {
        $TimeUnix = $Test.Date;
        $Index = $CommitIndexMap[$Test.CommitHash];
        foreach ($Result in $Test.Results) {
            $Data = "{x: $Index, t: new Date($TimeUnix), rawTime: $TimeUnix, y: $Result, machine: `"$($Test.MachineName)`"}";
            if ($DataVal -eq "") {
                $DataVal = $Data;
            } else {
                $DataVal = "$DataVal, $Data";
            }
        }
    }
    return "[$DataVal]";
}

function Get-AverageDataJs {
    param (
        [Parameter(Mandatory = $true)]
        $TestList,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    $DataVal = "";
    foreach ($Test in $TestList) {
        $TimeUnix = $Test.Date;
        $Average = ($Test.Results  | Measure-Object -Average).Average;
        $Index = $CommitIndexMap[$Test.CommitHash];
        $Data = "{x: $Index, t: new Date($TimeUnix), rawTime: $TimeUnix, y: $Average, machine: `"$($Test.MachineName)`"}";
        if ($DataVal -eq "") {
            $DataVal = $Data;
        } else {
            $DataVal = "$DataVal, $Data";
        }
    }
    return "[$DataVal]";
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
    [long]$Date;
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
        [string]$AvgReplaceName,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    $RawData = Get-RawTestDataJs -TestList $ThroughputTests -CommitIndexMap $CommitIndexMap
    $AvgData = Get-AverageDataJs -TestList $ThroughputTests -CommitIndexMap $CommitIndexMap

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
        [TestCommitModel[]]$CpuCommitData,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    # Dict<Config, Dict<Platform, List<Tests>>>
    $ThroughputTests = Get-ThroughputTests -CommitData $CpuCommitData

    $UploadDefault = Get-ThroughputDefault -Download $false

    $DownloadDefault = Get-ThroughputDefault -Download $true

    $UploadTests = $ThroughputTests[$UploadDefault];
    $DownloadTests = $ThroughputTests[$DownloadDefault];

    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_UP" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_UP" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_UP" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_UP" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_UP" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_UP" -CommitIndexMap $CommitIndexMap

    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_DOWN" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_THROUGHPUT_DOWN" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_DOWN" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_THROUGHPUT_DOWN" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_DOWN" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_THROUGHPUT_DOWN" -CommitIndexMap $CommitIndexMap

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
    [long]$Date;
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
        [string]$AvgReplaceName,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    $RawData = Get-RawTestDataJs -TestList $RpsTests -CommitIndexMap $CommitIndexMap
    $AvgData = Get-AverageDataJs -TestList $RpsTests -CommitIndexMap $CommitIndexMap

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
        [TestCommitModel[]]$CpuCommitData,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    # Dict<Config, Dict<Platform, List<Tests>>>
    $RpsTests = Get-RpsTests -CommitData $CpuCommitData

    $RpsDefault = Get-RpsDefault;

    $RpsTestConfig = $RpsTests[$RpsDefault];

    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_RPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_RPS" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_RPS" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_RPS" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_RPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_RPS" -CommitIndexMap $CommitIndexMap

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
    [long]$Date;
    [string]$MachineName;
    [double[]]$Results;
}

function Get-HpsTests {
    [OutputType([Collections.Generic.Dictionary[HpsConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[HpsTest]]]])]
    param (
        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$CommitData
    )
    $Tests = [Collections.Generic.Dictionary[HpsConfiguration, Collections.Generic.Dictionary[string, Collections.Generic.List[HpsTest]]]]::new()

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
        [string]$AvgReplaceName,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    $RawData = Get-RawTestDataJs -TestList $HpsTests -CommitIndexMap $CommitIndexMap
    $AvgData = Get-AverageDataJs -TestList $HpsTests -CommitIndexMap $CommitIndexMap

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
        [TestCommitModel[]]$CpuCommitData,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    # Dict<Config, Dict<Platform, List<Tests>>>
    $HpsTests = Get-HpsTests -CommitData $CpuCommitData

    $HpsDefault = Get-HpsDefault;

    $HpsTestConfig = $HpsTests[$HpsDefault];

    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Windows_x64_schannel"] -RawReplaceName "RAW_DATA_WINDOWS_X64_SCHANNEL_HPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_SCHANNEL_HPS" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Winkernel_x64_schannel"] -RawReplaceName "RAW_DATA_WINKERNEL_X64_SCHANNEL_HPS" -AvgReplaceName "AVERAGE_DATA_WINKERNEL_X64_SCHANNEL_HPS" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Windows_x64_openssl"] -RawReplaceName "RAW_DATA_WINDOWS_X64_OPENSSL_HPS" -AvgReplaceName "AVERAGE_DATA_WINDOWS_X64_OPENSSL_HPS" -CommitIndexMap $CommitIndexMap

    return $DataFile
}

#endregion

#region latency
function Get-LatencyDataJs {
    param (
        $File)

    $Data = Get-Content -Path $File
    $DataVal = ""
    foreach ($Line in $Data) {
        if ([string]::IsNullOrWhiteSpace($Line)) {
            continue;
        }
        if ($Line.Trim().StartsWith("#")) {
            continue;
        }
        if ($Line.Trim().StartsWith("Value")) {
            continue;
        }
        $Split = $Line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries);
        $XVal = $Split[3];
        $YVal = $Split[0];
        $OutVar = 0.0
        if (![double]::TryParse($XVal, [Ref]$OutVar) -or ![double]::TryParse($YVal, [Ref]$OutVar)) {
            continue
        }
        #$XVal = 100.0 - (100.0 / $XVal);
        $ToWrite = "{x: $XVal, y: $YVal}"
        if ($DataVal -eq "") {
            $DataVal = $ToWrite
        } else {
            $DataVal = "$DataVal, $ToWrite"
        }

        # [{x: ..., y: ...}, {}]
    }
    return "[$DataVal]"
}
#endregion

#region Commits

function Get-CommitTableDataJs {
    param (
        [TestCommitModel[]]$CpuCommitData
    )

    $DataVal = "";

    foreach ($Commit in $CpuCommitData) {
        $TimeUnix = $Commit.Date
        $Data = "{commitHash: `"$($Commit.CommitHash)`", commitDate: $TimeUnix}";
        if ($DataVal -eq "") {
            $DataVal = $Data;
        } else {
            $DataVal = "$DataVal, $Data";
        }
    }

    return "[$DataVal]";
}

#endregion

$RootDir = Split-Path $PSScriptRoot -Parent
$BranchFolder = Join-Path $RootDir 'data' $BranchName

$CommitHistory = Get-CommitHistory -DaysToReceive $DaysToReceive -MinimumCommits 5 -MaximumCommits 0 -BranchFolder $BranchFolder
$CpuCommitData = Get-CpuCommitData -CommitHistory $CommitHistory -BranchFolder $BranchFolder

$DataFileIn = Join-Path $RootDir "assets" "summary" "data.js.in"
$DataFileContents = Get-Content $DataFileIn

$FirstAndLast = $CommitHistory | Sort-Object -Property Date | Select-Object -Index 0, ($CommitHistory.Count - 1)

$OldestDateString = $FirstAndLast[0].Date;
if ($FirstAndLast.Count -eq 1) {
    $NewestDateString = $FirstAndLast[0].Date;
} else {
    $NewestDateString = $FirstAndLast[1].Date;
}

$DataFileContents = $DataFileContents.Replace("NEWEST_DATE", "new Date($NewestDateString)")
$DataFileContents = $DataFileContents.Replace("OLDEST_DATE", "new Date($OldestDateString)")
$DataFileContents = $DataFileContents.Replace("MAX_INDEX", $CommitHistory.Count)

$CommitIndexMap = @{}
$Index = $CommitHistory.Length - 1
foreach ($Item in $CommitHistory) {
    $CommitIndexMap.Add($Item.CommitHash, $Index)
    $Index--
}

$DataFileContents = $DataFileContents.Replace("COMMIT_DATE_PAIR", (Get-CommitTimePairJs -CommitModel $CommitHistory))

$DataFileContents = Get-ThroughputTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-RpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-HpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap

# Grab Latency Data
$LatestCommit = Get-LatestCommit -BranchFolder $BranchFolder
$LatencyFolder = Join-Path $BranchFolder $LatestCommit.CommitHash "RpsLatency"
$WinOpenSslLatencyFile = Join-Path $LatencyFolder "histogram_RPS_Windows_x64_openssl_ConnectionCount_40.txt"
$WinSchannelLatencyFile = Join-Path $LatencyFolder "histogram_RPS_Windows_x64_schannel_ConnectionCount_40.txt"
$WinKernelLatencyFile = Join-Path $LatencyFolder "histogram_RPS_Winkernel_x64_schannel_ConnectionCount_40.txt"

$WinOpenSslData = Get-LatencyDataJs -File $WinOpenSslLatencyFile
$WinSchannelData = Get-LatencyDataJs -File $WinSchannelLatencyFile
$WinKernelData = Get-LatencyDataJs -File $WinKernelLatencyFile

$DataFileContents = $DataFileContents.Replace("RPS_LATENCY_WINDOWS_OPENSSL", $WinOpenSslData)
$DataFileContents = $DataFileContents.Replace("RPS_LATENCY_WINDOWS_SCHANNEL", $WinSchannelData)
$DataFileContents = $DataFileContents.Replace("RPS_LATENCY_WINKERNEL", $WinKernelData)

$OutputFolder = Join-Path $RootDir "assets" "summary" $BranchName
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
$DataFileOut = Join-Path $OutputFolder "data.js"
$DataFileContents | Set-Content $DataFileOut

$CommitsTableTemplate = Get-Content (Join-Path $RootDir "assets" "summary" "data.commits.js.in")
$CommitTableJs = Get-CommitTableDataJs -CpuCommitData $CpuCommitData
$CommitsTableTemplate = $CommitsTableTemplate.Replace("COMMIT_DATA", $CommitTableJs);
$DataFileOut = Join-Path $OutputFolder "data.commits.js"
$CommitsTableTemplate | Set-Content $DataFileOut

# Grab per commit pages

$CommitHistory = Get-CommitHistory -DaysToReceive $DaysToReceive -MinimumCommits 5 -MaximumCommits 5 -BranchFolder $BranchFolder
$CpuCommitData = Get-CpuCommitData -CommitHistory $CommitHistory -BranchFolder $BranchFolder
$CurrentCommitHash = $CommitHistory[0].CommitHash

$TemplateFolder = $DataFileIn = Join-Path $RootDir "assets" "percommit"
$DataFileIn = Join-Path $TemplateFolder "data.js.in"
$DataFileContents = Get-Content $DataFileIn

$FirstAndLast = $CommitHistory | Sort-Object -Property Date | Select-Object -Index 0, ($CommitHistory.Count - 1)

$OldestDateString = $FirstAndLast[0].Date;
if ($FirstAndLast.Count -eq 1) {
    $NewestDateString = $FirstAndLast[0].Date;
} else {
    $NewestDateString = $FirstAndLast[1].Date;
}

$DataFileContents = $DataFileContents.Replace("NEWEST_DATE", "new Date($NewestDateString)")
$DataFileContents = $DataFileContents.Replace("OLDEST_DATE", "new Date($OldestDateString)")
$DataFileContents = $DataFileContents.Replace("MAX_INDEX", $CommitHistory.Count)
$DataFileContents = $DataFileContents.Replace("PAGE_COMMIT_HASH", "`"$CurrentCommitHash`"")

$CommitIndexMap = @{}
$Index = $CommitHistory.Length - 1
foreach ($Item in $CommitHistory) {
    $CommitIndexMap.Add($Item.CommitHash, $Index)
    $Index--
}

$DataFileContents = Get-ThroughputTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-RpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-HpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap

$DataFileContents = $DataFileContents.Replace("COMMIT_DATE_PAIR", (Get-CommitTimePairJs -CommitModel $CommitHistory))

# Grab Latency Data
$LatestCommit = Get-LatestCommit -BranchFolder $BranchFolder
$LatencyFolder = Join-Path $BranchFolder $LatestCommit.CommitHash "RpsLatency"
$WinOpenSslLatencyFile = Join-Path $LatencyFolder "histogram_RPS_Windows_x64_openssl_Default.txt"
$WinSchannelLatencyFile = Join-Path $LatencyFolder "histogram_RPS_Windows_x64_schannel_Default.txt"
$WinKernelLatencyFile = Join-Path $LatencyFolder "histogram_RPS_Winkernel_x64_schannel_Default.txt"

$WinOpenSslData = Get-LatencyDataJs -File $WinOpenSslLatencyFile
$WinSchannelData = Get-LatencyDataJs -File $WinSchannelLatencyFile
$WinKernelData = Get-LatencyDataJs -File $WinKernelLatencyFile

$DataFileContents = $DataFileContents.Replace("RPS_LATENCY_WINDOWS_OPENSSL", $WinOpenSslData)
$DataFileContents = $DataFileContents.Replace("RPS_LATENCY_WINDOWS_SCHANNEL", $WinSchannelData)
$DataFileContents = $DataFileContents.Replace("RPS_LATENCY_WINKERNEL", $WinKernelData)

$OutputFolder = Join-Path $RootDir 'percommit' $BranchName $CurrentCommitHash
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
$DataFileOut = Join-Path $OutputFolder "data.js"
$DataFileContents | Set-Content $DataFileOut

# Take template folder, and copy to commit
Copy-Item -Path $TemplateFolder/* -Destination $OutputFolder -Exclude "data.js.in" -Force
