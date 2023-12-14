<#

.SYNOPSIS
This takes merged performance results and generates graphs to display.
This is ran from merge-performance.ps1

#>

Using module .\mergetypes.psm1

param (
    [Parameter(Mandatory = $false)]
    [string]$BranchName = "main",

    [Parameter(Mandatory = $false)]
    [int]$DaysToReceive = 365
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

    $Results = [System.Collections.ArrayList]@();

    foreach ($SingleCommitHis in $CommitHistory) {
        $CommitDataFile = Join-Path $BranchFolder $SingleCommitHis.CommitHash "cpu_data.json"
        $null = $Results.Add((Get-Content $CommitDataFile | ConvertFrom-Json));
    }

    return $Results.ToArray();
}

function Get-RawTestDataJs {
    param (
        [Parameter(Mandatory = $true)]
        $TestList,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    $Results = [System.Collections.ArrayList]@();
    foreach ($Test in $TestList) {
        $Index = $CommitIndexMap[$Test.CommitHash];
        $Build = 0
        $Machine = ""
        if ($Test.MachineName.Contains(":")) {
            $Build = [Int32]$Test.MachineName.Split(":")[0];
            $Machine = $Test.MachineName.Split(":")[1];
        } else {
            $Machine = $Test.MachineName
        }
        $Machine = $Machine.Substring($Machine.Length-2)
        $Data = "{c:$Index,m:`"$Machine`",b:$Build,d:[$($Test.Results -Join ",")]}";
        $null = $Results.Add($Data);
    }
    return "[$($Results -Join ",")]";
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
            if ($null -eq $Test.TputConfig -or $Test.TestName.StartsWith("Tcp")) {
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
        [hashtable]$CommitIndexMap
    )

    $RawData = Get-RawTestDataJs -TestList $ThroughputTests -CommitIndexMap $CommitIndexMap
    $DataFile = $DataFile.Replace($RawReplaceName, $RawData)
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

    Write-Debug "Generating Get-RpsTestsJs"

    # Dict<Config, Dict<Platform, List<Tests>>>
    $ThroughputTests = Get-ThroughputTests -CommitData $CpuCommitData

    $UploadDefault = Get-ThroughputDefault -Download $false

    $DownloadDefault = Get-ThroughputDefault -Download $true

    $UploadTests = $ThroughputTests[$UploadDefault];
    $DownloadTests = $ThroughputTests[$DownloadDefault];

    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Windows_x64_schannel"] -RawReplaceName "UP_WINDOWS_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Winkernel_x64_schannel"] -RawReplaceName "UP_WINKERNEL_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["WinXDP_x64_schannel"] -RawReplaceName "UP_WINXDP_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["Windows_x64_openssl"] -RawReplaceName "UP_WINDOWS_X64_OPENSSL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $UploadTests["linux_x64_openssl"] -RawReplaceName "UP_LINUX_X64_OPENSSL" -CommitIndexMap $CommitIndexMap

    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Windows_x64_schannel"] -RawReplaceName "DOWN_WINDOWS_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Winkernel_x64_schannel"] -RawReplaceName "DOWN_WINKERNEL_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["WinXDP_x64_schannel"] -RawReplaceName "DOWN_WINXDP_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["Windows_x64_openssl"] -RawReplaceName "DOWN_WINDOWS_X64_OPENSSL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-ThroughputPlatformTests -DataFile $DataFile -ThroughputTests $DownloadTests["linux_x64_openssl"] -RawReplaceName "DOWN_LINUX_X64_OPENSSL" -CommitIndexMap $CommitIndexMap

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
            if ($null -eq $Test.RpsConfig -or $Test.TestName.StartsWith("Tcp")) {
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
        [hashtable]$CommitIndexMap
    )

    $RawData = Get-RawTestDataJs -TestList $RpsTests -CommitIndexMap $CommitIndexMap
    $DataFile = $DataFile.Replace($RawReplaceName, $RawData)
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

    Write-Debug "Generating Get-RpsTestsJs"

    # Dict<Config, Dict<Platform, List<Tests>>>
    $RpsTests = Get-RpsTests -CommitData $CpuCommitData

    $RpsDefault = Get-RpsDefault;

    $RpsTestConfig = $RpsTests[$RpsDefault];

    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Windows_x64_schannel"] -RawReplaceName "RPS_WINDOWS_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Winkernel_x64_schannel"] -RawReplaceName "RPS_WINKERNEL_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["WinXDP_x64_schannel"] -RawReplaceName "RPS_WINXDP_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["Windows_x64_openssl"] -RawReplaceName "RPS_WINDOWS_X64_OPENSSL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-RpsPlatformTests -DataFile $DataFile -RpsTests $RpsTestConfig["linux_x64_openssl"] -RawReplaceName "RPS_LINUX_X64_OPENSSL" -CommitIndexMap $CommitIndexMap

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
            if ($null -eq $Test.HpsConfig -or $Test.TestName.StartsWith("Tcp")) {
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
        [hashtable]$CommitIndexMap
    )

    $RawData = Get-RawTestDataJs -TestList $HpsTests -CommitIndexMap $CommitIndexMap
    $DataFile = $DataFile.Replace($RawReplaceName, $RawData)
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

    Write-Debug "Generating Get-HpsTestsJs"

    # Dict<Config, Dict<Platform, List<Tests>>>
    $HpsTests = Get-HpsTests -CommitData $CpuCommitData

    $HpsDefault = Get-HpsDefault;

    $HpsTestConfig = $HpsTests[$HpsDefault];

    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Windows_x64_schannel"] -RawReplaceName "HPS_WINDOWS_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Winkernel_x64_schannel"] -RawReplaceName "HPS_WINKERNEL_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["WinXDP_x64_schannel"] -RawReplaceName "HPS_WINXDP_X64_SCHANNEL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["Windows_x64_openssl"] -RawReplaceName "HPS_WINDOWS_X64_OPENSSL" -CommitIndexMap $CommitIndexMap
    $DataFile = Get-HpsPlatformTests -DataFile $DataFile -HpsTests $HpsTestConfig["linux_x64_openssl"] -RawReplaceName "HPS_LINUX_X64_OPENSSL" -CommitIndexMap $CommitIndexMap

    return $DataFile
}

#endregion

#region latency

function Get-LatencyData {
    param (
        $File)
    $Data = Get-Content -Path $File
    $Results = [System.Collections.ArrayList]@();

    foreach ($Line in $Data) {
        if ([string]::IsNullOrWhiteSpace($Line) -or $Line.Trim().StartsWith("#") -or $Line.Trim().StartsWith("Value")) {
            continue;
        }
        $Split = $Line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries);
        $YVal = $Split[0];
        $XVal = $Split[1];
        $OutVar = 0.0
        if (![double]::TryParse($XVal, [Ref]$OutVar) -or ![double]::TryParse($YVal, [Ref]$OutVar)) {
            continue
        }

        $null = $Results.Add(@($XVal, $YVal));
    }
    return $Results
}

function Get-PercentileFromLatencyFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [double]$Percentile # as a fraction (i.e. 0.9 for 90%)
    )

    #Write-Debug "Searching for $Percentile percentile in $FilePath"

    $LatencyResults = Get-LatencyData $FilePath
    $LatencyResults = $LatencyResults | Where-Object {[double]$_[0] -ge $Percentile} | Select-Object -First 1 # Find P90
    #Write-Debug "Found: $($LatencyResults[1])"
    return [double]$LatencyResults[1]
}

function Get-MedianLatencyFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$BranchFolder,

        [Parameter(Mandatory = $true)]
        [string]$CommitHash,

        [Parameter(Mandatory = $true)]
        [string]$TestName,

        [Parameter(Mandatory = $true)]
        [double]$Percentile # as a fraction (i.e. 0.9 for 90%)
    )

    $LatencyFolder = Join-Path $BranchFolder $CommitHash "RpsLatency"

    #Write-Debug "Searching for median latency file in $LatencyFolder for $TestName"

    if (Test-Path (Join-Path $LatencyFolder "histogram_$TestName.txt")) {
        # This is the old (single file) model
        #Write-Debug "Found histogram_$TestName.txt"
        return Join-Path $LatencyFolder "histogram_$TestName.txt"
    }

    if (!(Test-Path (Join-Path $LatencyFolder "$($TestName)_run1.txt"))) {
        #Write-Debug "Missing!"
        return $null # Data is just missing
    }

    # Get all the different runs
    $LatencyFilesPaths = Join-Path $LatencyFolder "$($TestName)_run*.txt"
    $LatencyFiles = Get-ChildItem -Path $LatencyFilesPaths -Recurse -File

    # Find all the percentiles for the runs
    $Percentiles = [System.Collections.ArrayList]@();
    foreach ($File in $LatencyFiles) {
        $_ = $Percentiles.Add(@((Get-PercentileFromLatencyFile $File $Percentile), $File));
    }

    $Sorted = $Percentiles | Sort-Object -Property {$_[0]}
    $MedianFile = $Sorted[[int](($Sorted.Length - 1) / 2)][1] # Assumes an odd Length
    #Write-Debug "Found $MedianFile"
    return [String]$MedianFile
}

function Get-PerCommitLatencyDataJs {
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [CommitsFileModel[]]$CommitHistory,

        [Parameter(Mandatory = $true)]
        [string]$BranchFolder,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommitIndexMap
    )

    Write-Debug "Generating PerCommitLatencyDataJs"

    $DataStrings = @{};
    $platformNames = @("linux_x64_openssl", "Windows_x64_openssl", "Windows_x64_schannel", "Winkernel_x64_schannel", "WinXDP_x64_schannel");
    $connCounts = @("1", "40");
    foreach ($platformName in $platformNames) {
        $platformResults = [System.Collections.ArrayList]@();
        foreach ($SingleCommitHis in $CommitHistory) {
            foreach ($connCount in $connCounts) {
                $LatencyFile = Get-MedianLatencyFile $BranchFolder $SingleCommitHis.CommitHash "RPS_${platformName}_ConnectionCount_${connCount}" 0.9
                if ($null -eq $LatencyFile) {
                    continue;
                }
                $Latency = Get-PercentileFromLatencyFile $LatencyFile 0.9
                $null = $platformResults.Add("{c:${connCount},x:$($CommitIndexMap[$SingleCommitHis.CommitHash]),y:$Latency}");
            }
        }
        $DataStrings[$platformName] = "[$($platformResults -Join ",")]";
    }

    # Replace RPS latency template variables
    foreach ($key in $DataStrings.keys) {
        $DataFile = $DataFile.Replace("RPS_LATENCY_$($key.ToUpper())", $DataStrings[$key])
    }

    return $DataFile;
}

function Get-LatestLatencyData {
    param (
        $File)

    Write-Debug "Getting latest data for $File"

    $Data = Get-Content -Path $File
    $Results = [System.Collections.ArrayList]@();
    foreach ($Line in $Data) {
        if ([string]::IsNullOrWhiteSpace($Line) -or $Line.Trim().StartsWith("#") -or $Line.Trim().StartsWith("Value")) {
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
        $ToWrite = "{x:$XVal,y:$YVal}"
        $null = $Results.Add($ToWrite);
    }
    # [{x: ..., y: ...}, {}]
    return "[$($Results -Join ",")]"
}

function Get-LatestLatencyDataJs {
    param (
        [Parameter(Mandatory = $true)]
        $DataFile,

        [Parameter(Mandatory = $true)]
        [string]$BranchFolder
    )

    $connCounts = @("1", "40");
    foreach ($c in $connCounts) {
        Write-Debug "Generating LatestLatencyDataJs"

        # Grab Latency Data
        $LatestCommit = Get-LatestCommit -BranchFolder $BranchFolder
        $LinuxOpenSslLatencyFile = Get-MedianLatencyFile $BranchFolder $LatestCommit.CommitHash "RPS_linux_x64_openssl_ConnectionCount_$c" 0.9
        $WinOpenSslLatencyFile = Get-MedianLatencyFile $BranchFolder $LatestCommit.CommitHash "RPS_Windows_x64_openssl_ConnectionCount_$c" 0.9
        $WinSchannelLatencyFile = Get-MedianLatencyFile $BranchFolder $LatestCommit.CommitHash "RPS_Windows_x64_schannel_ConnectionCount_$c" 0.9
        $WinKernelLatencyFile = Get-MedianLatencyFile $BranchFolder $LatestCommit.CommitHash "RPS_Winkernel_x64_schannel_ConnectionCount_$c" 0.9
        $WinXDPLatencyFile = Get-MedianLatencyFile $BranchFolder $LatestCommit.CommitHash "RPS_WinXDP_x64_schannel_ConnectionCount_$c" 0.9

        Write-Debug "Generating data for median files"

        $LinuxOpenSslData = Get-LatestLatencyData $LinuxOpenSslLatencyFile
        $WinOpenSslData = Get-LatestLatencyData $WinOpenSslLatencyFile
        $WinSchannelData = Get-LatestLatencyData $WinSchannelLatencyFile
        $WinKernelData = Get-LatestLatencyData $WinKernelLatencyFile
        $WinXDPData = Get-LatestLatencyData $WinXDPLatencyFile

        Write-Debug "Writing data for median files"

        $DataFile = $DataFile.Replace("RPS_LATENCY_$($c)_LATEST_LINUX_X64_OPENSSL", $LinuxOpenSslData)
        $DataFile = $DataFile.Replace("RPS_LATENCY_$($c)_LATEST_WINDOWS_X64_OPENSSL", $WinOpenSslData)
        $DataFile = $DataFile.Replace("RPS_LATENCY_$($c)_LATEST_WINDOWS_X64_SCHANNEL", $WinSchannelData)
        $DataFile = $DataFile.Replace("RPS_LATENCY_$($c)_LATEST_WINKERNEL_X64_SCHANNEL", $WinKernelData)
        $DataFile = $DataFile.Replace("RPS_LATENCY_$($c)_LATEST_WINXDP_X64_SCHANNEL", $WinXDPData)
    }

    return $DataFile
}
#endregion

#region Commits

function Get-RecentCommitsJs {
    param (
        [TestCommitModel[]]$CpuCommitData
    )

    $Results = [System.Collections.ArrayList]@();
    foreach ($Commit in $CpuCommitData) {
        $TimeUnix = $Commit.Date
        $Data = "{h:`"$($Commit.CommitHash)`", t:$TimeUnix}";
        $null = $Results.Add($Data);
    }

    $Results.Reverse();
    return "[$($Results -Join ",")]";
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

$DataFileContents = $DataFileContents.Replace("RECENT_COMMITS", (Get-RecentCommitsJs -CpuCommitData $CpuCommitData))

$DataFileContents = Get-ThroughputTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-RpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-HpsTestsJs -DataFile $DataFileContents -CpuCommitData $CpuCommitData -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-PerCommitLatencyDataJs -DataFile $DataFileContents -CommitHistory $CommitHistory -BranchFolder $BranchFolder -CommitIndexMap $CommitIndexMap
$DataFileContents = Get-LatestLatencyDataJs -DataFile $DataFileContents -BranchFolder $BranchFolder

$OutputFolder = Join-Path $RootDir "assets" "summary" $BranchName
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
$DataFileOut = Join-Path $OutputFolder "data.js"
$DataFileContents | Set-Content $DataFileOut
