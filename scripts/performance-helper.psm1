# Helper functions for msquic performance testing. As this is a module, this cannot be called directly.

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

#region Stack Walk Profiles

# WPA Profile for collecting stacks.
$WpaStackWalkProfileXml = `
@"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0" Author="MsQuic" Copyright="Microsoft Corporation" Company="Microsoft Corporation">
  <Profiles>
    <SystemCollector Id="SC_HighVolume" Realtime="false">
      <BufferSize Value="1024"/>
      <Buffers Value="80"/>
    </SystemCollector>
    <SystemProvider Id="SP_CPU">
      <Keywords>
        <Keyword Value="CpuConfig"/>
        <Keyword Value="Loader"/>
        <Keyword Value="ProcessThread"/>
        <Keyword Value="SampledProfile"/>
      </Keywords>
      <Stacks>
        <Stack Value="SampledProfile"/>
      </Stacks>
    </SystemProvider>
    <Profile Id="CPU.Light.File" Name="CPU" Description="CPU Stacks" LoggingMode="File" DetailLevel="Light">
      <Collectors>
        <SystemCollectorId Value="SC_HighVolume">
          <SystemProviderId Value="SP_CPU" />
        </SystemCollectorId>
      </Collectors>
    </Profile>
  </Profiles>
</WindowsPerformanceRecorder>
"@

# WPA Profile for collecting QUIC Logs.
$WpaQUICLogProfileXml = `
@"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0" Author="MsQuic" Copyright="Microsoft Corporation" Company="Microsoft Corporation">
  <Profiles>
    <SystemCollector Id="SC_HighVolume" Realtime="false">
      <BufferSize Value="1024"/>
      <Buffers Value="80"/>
    </SystemCollector>
    <EventCollector Id="EC_LowVolume" Realtime="false" Name="LowVolume">
      <BufferSize Value="1024"/>
      <Buffers Value="80"/>
    </EventCollector>
    <SystemProvider Id="SP_CPU">
      <Keywords>
        <Keyword Value="CpuConfig"/>
        <Keyword Value="Loader"/>
        <Keyword Value="ProcessThread"/>
        <Keyword Value="SampledProfile"/>
      </Keywords>
      <Stacks>
        <Stack Value="SampledProfile"/>
      </Stacks>
    </SystemProvider>
    <EventProvider Id="MsQuicEtwPerf" Name="ff15e657-4f26-570e-88ab-0796b258d11c" NonPagedMemory="true" Level="5">
      <Keywords>
        <Keyword Value="0xE0000000"/>
      </Keywords>
    </EventProvider>
    <Profile Id="CPU.Light.File" Name="CPU" Description="CPU Stacks" LoggingMode="File" DetailLevel="Light">
      <Collectors>
        <SystemCollectorId Value="SC_HighVolume">
          <SystemProviderId Value="SP_CPU" />
        </SystemCollectorId>
        <EventCollectorId Value="EC_LowVolume">
          <EventProviders>
            <EventProviderId Value="MsQuicEtwPerf" />
          </EventProviders>
        </EventCollectorId>
      </Collectors>
    </Profile>
  </Profiles>
</WindowsPerformanceRecorder>
"@

#endregion

function Set-ScriptVariables {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param ($Local, $LocalTls, $LocalArch, $RemoteTls, $RemoteArch, $Config, $Publish, $Record, $RecordQUIC, $RemoteAddress, $Session, $Kernel)
    $script:Local = $Local
    $script:LocalTls = $LocalTls
    $script:LocalArch = $LocalArch
    $script:RemoteTls = $RemoteTls
    $script:RemoteArch = $RemoteArch
    $script:Config = $Config
    $script:Publish = $Publish
    $script:Record = $Record
    $script:RecordQUIC = $RecordQUIC
    $script:RemoteAddress = $RemoteAddress
    $script:Session = $Session
    $script:Kernel = $Kernel
    if ($null -ne $Session) {
        Invoke-Command -Session $Session -ScriptBlock {
            $ErrorActionPreference = "Stop"
        }
    }
}

function Set-Session {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param ($Session)

}

function Convert-HostToNetworkOrder {
    param ($Address)
    $Bytes = $Address.GetAddressBytes()
    [Array]::Reverse($Bytes) | Out-Null
    return [System.BitConverter]::ToUInt32($Bytes, 0)
}

function Get-LocalAddress {
    param ($RemoteAddress)
    $PossibleRemoteIPs = [System.Net.Dns]::GetHostAddresses($RemoteAddress) | Select-Object -Property IPAddressToString
    $PossibleLocalIPs = Get-NetIPAddress -AddressFamily IPv4 | Select-Object -Property IPv4Address, PrefixLength
    $MatchedIPs = @()
    $PossibleLocalIPs | ForEach-Object {

        [IPAddress]$LocalIpAddr = $_.IPv4Address

        $ToMaskLocalAddress = Convert-HostToNetworkOrder -Address $LocalIpAddr

        $Mask = (1ul -shl $_.PrefixLength) - 1
        $Mask = $Mask -shl (32 - $_.PrefixLength)
        $LocalSubnet = $ToMaskLocalAddress -band $Mask

        $PossibleRemoteIPs | ForEach-Object {
            [ipaddress]$RemoteIpAddr = $_.IPAddressToString
            $ToMaskRemoteAddress = Convert-HostToNetworkOrder($RemoteIpAddr)
            $RemoteMasked = $ToMaskRemoteAddress -band $Mask

            if ($RemoteMasked -eq $LocalSubnet) {
                $MatchedIPs += $LocalIpAddr.IPAddressToString
            }
        }
    }

    if ($MatchedIPs.Length -ne 1) {
        Write-Error "Failed to parse local address matching remote"
    }

    return $MatchedIPs[0]
}

function Invoke-TestCommand {
    param ($Session, $ScriptBlock, [Object[]]$ArgumentList = @(), [switch]$AsJob = $false)
    if ($Local) {
        if ($AsJob) {
            return Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        }
        return Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    } else {
        if ($AsJob) {
            return Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -AsJob -ArgumentList $ArgumentList
        }
        return Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }
}

function Wait-ForRemoteReady {
    param ($Job, $Matcher)
    $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    while ($StopWatch.ElapsedMilliseconds -lt 10000) {
        $CurrentResults = Receive-Job -Job $Job -Keep
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            $DidMatch = $CurrentResults -match $Matcher
            if ($DidMatch) {
                return $true
            }
        }
        Start-Sleep -Seconds 0.1 | Out-Null
    }
    return $false
}

function Wait-ForRemote {
    param ($Job)
    # Ping sidechannel socket on 9999 to tell the app to die
    $Socket = New-Object System.Net.Sockets.UDPClient
    $Socket.Send(@(1), 1, $RemoteAddress, 9999) | Out-Null
    Wait-Job -Job $Job -Timeout 120 | Out-Null
    Stop-Job -Job $Job | Out-Null
    $RetVal = Receive-Job -Job $Job
    return $RetVal -join "`n"
}

function Copy-Artifacts {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    param ([string]$From, [string]$To)
    Remove-PerfServices
    Invoke-TestCommand $Session -ScriptBlock {
        param ($To)
        try {
            Remove-Item -Path "$To/*" -Recurse -Force
        } catch [System.Management.Automation.ItemNotFoundException] {
            # Ignore Not Found for when the directory does not exist
            # This will still throw if a file cannot successfuly be deleted
        }

    } -ArgumentList $To
    Copy-Item -Path "$From\*" -Destination $To -ToSession $Session  -Recurse -Force
}

function Get-GitHash {
    param ($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RepoDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentCommitHash = $null
    try {
        $CurrentCommitHash = git rev-parse HEAD
    } catch {
        Write-Debug "Failed to get commit hash from git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $CurrentCommitHash
}

function Get-ExePath {
    param ($PathRoot, $Platform, $IsRemote)
    if ($IsRemote) {
        $ConfigStr = "$($RemoteArch)_$($Config)_$($RemoteTls)"
        return Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($PathRoot, $Platform, $ConfigStr)
            Join-Path $PathRoot $Platform $ConfigStr
        } -ArgumentList $PathRoot, $Platform, $ConfigStr
    } else {
        $ConfigStr = "$($LocalArch)_$($Config)_$($LocalTls)"
        return Join-Path $PathRoot $Platform $ConfigStr
    }
}

function Get-ExeName {
    param ($PathRoot, $Platform, $IsRemote, $TestPlat)
    $ExeName = $TestPlat.Exe
    if ($Platform -eq "windows") {
        $ExeName += ".exe"
    }

    if ($IsRemote) {
        $ConfigStr = "$($RemoteArch)_$($Config)_$($RemoteTls)"
        return Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($PathRoot, $Platform, $ConfigStr, $ExeName)
            Join-Path $PathRoot $Platform $ConfigStr $ExeName
        } -ArgumentList $PathRoot, $Platform, $ConfigStr, $ExeName
    } else {
        $ConfigStr = "$($LocalArch)_$($Config)_$($LocalTls)"
        return Join-Path $PathRoot $Platform $ConfigStr $ExeName
    }
}

function Remove-PerfServices {
    if ($IsWindows) {
        Invoke-TestCommand -Session $Session -ScriptBlock {
            if ($null -ne (Get-Service -Name "quicperf" -ErrorAction Ignore)) {
                try {
                    net.exe stop quicperf /y | Out-Null
                }
                catch {}
                sc.exe delete quicperf /y | Out-Null
            }
            if ($null -ne (Get-Service -Name "msquicpriv" -ErrorAction Ignore)) {
                try {
                    net.exe stop msquicpriv /y | Out-Null
                }
                catch {}
                sc.exe delete msquicpriv /y | Out-Null
            }
        }
    }
}

function Invoke-RemoteExe {
    param ($Exe, $RunArgs)

    # Command to run chmod if necessary, and get base path
    $BasePath = Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($Exe)
        if (!$IsWindows) {
            chmod +x $Exe
            return Split-Path $Exe -Parent
        }
        return $null
    } -ArgumentList $Exe

    if ($Kernel) {
        $RunArgs = "--kernel $RunArgs"
    }

    Write-Debug "Running Remote: $Exe $RunArgs"

    $WpaXml = $WpaStackWalkProfileXml
    if ($RecordQUIC) {
        $WpaXml = $WpaQUICLogProfileXml
    }

    return Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($Exe, $RunArgs, $BasePath, $Record, $WpaXml, $Kernel)
        if ($null -ne $BasePath) {
            $env:LD_LIBRARY_PATH = $BasePath
        }

        if ($Record -and $IsWindows) {
            $EtwXmlName = $Exe + ".remote.wprp"

            $WpaXml | Out-File $EtwXmlName
            wpr.exe -start $EtwXmlName -filemode 2> $null
        }

        $Arch = Split-Path (Split-Path $Exe -Parent) -Leaf
        $RootBinPath = Split-Path (Split-Path (Split-Path $Exe -Parent) -Parent) -Parent
        $KernelDir = Join-Path $RootBinPath "winkernel" $Arch

        if ($Kernel) {
            Copy-Item (Join-Path $KernelDir "quicperf.sys") (Split-Path $Exe -Parent)
            Copy-Item (Join-Path $KernelDir "msquicpriv.sys") (Split-Path $Exe -Parent)
            sc.exe create "msquicpriv" type= kernel binpath= (Join-Path (Split-Path $Exe -Parent) "msquicpriv.sys") start= demand | Out-Null
            net.exe start msquicpriv
        }

        & $Exe ($RunArgs).Split(" ")

        # Uninstall the kernel mode test driver and revert the msquic driver.
        if ($Kernel) {
            net.exe stop msquicpriv /y | Out-Null
            sc.exe delete quicperf | Out-Null
            sc.exe delete msquicpriv | Out-Null
        }

        if ($Record -and $IsWindows) {
            $EtwName = $Exe + ".remote.etl"
            wpr.exe -stop $EtwName 2> $null
        }
    } -AsJob -ArgumentList $Exe, $RunArgs, $BasePath, $Record, $WpaXml, $Kernel
}

function Get-RemoteFile {
    param ($From, $To)

    if ($Local) {
        Copy-Item -Path $From -Destination $To
    } else {
        Copy-Item -Path $From -Destination $To -FromSession $Session
    }
}

function Remove-RemoteFile {
    param ($Path)
    if ($Local) {
        Remove-Item -Path $Path -Force
    } else {
        Invoke-Command -Session $Session -ScriptBlock { Remove-Item -Path $using:Path -Force }
    }
}

function Start-Tracing {
    param($Exe)
    if ($Record -and $IsWindows -and !$Local) {
        $EtwXmlName = $Exe + ".local.wprp"

        $WpaXml = $WpaStackWalkProfileXml
        if ($RecordQUIC) {
            $WpaXml = $WpaQUICLogProfileXml
        }

        $WpaXml | Out-File $EtwXmlName
        wpr.exe -start $EtwXmlName -filemode 2> $null
    }
}

function Stop-Tracing {
    param($Exe)
    if ($Record -and $IsWindows -and !$Local) {
        $EtwName = $Exe + ".local.etl"
        wpr.exe -stop $EtwName 2> $null
    }
}

function Merge-PGOCounts {
    param ($Path, $OutputDir)
    $Command = "$Path\pgomgr.exe /merge $Path $Path\msquic.pgd"
    Invoke-Expression $Command | Write-Debug
    Remove-Item "$Path\*.pgc" | Out-Null
}

function Invoke-LocalExe {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    param ($Exe, $RunArgs, $Timeout)
    if (!$IsWindows) {
        $BasePath = Split-Path $Exe -Parent
        $env:LD_LIBRARY_PATH = $BasePath
        chmod +x $Exe | Out-Null
    }
    $FullCommand = "$Exe $RunArgs"
    Write-Debug "Running Locally: $FullCommand"

    $Stopwatch =  [system.diagnostics.stopwatch]::StartNew()

    $LocalJob = Start-Job -ScriptBlock { & $Using:Exe ($Using:RunArgs).Split(" ") }

    # Wait for the job to finish
    Wait-Job -Job $LocalJob -Timeout $Timeout | Out-Null
    Stop-Job -Job $LocalJob | Out-Null

    $RetVal = Receive-Job -Job $LocalJob

    $Stopwatch.Stop()

    Write-Host ("Test Run Took " + $Stopwatch.Elapsed)

    return $RetVal -join "`n"
}

function Get-MedianTestResults($FullResults) {
    $sorted = $FullResults | Sort-Object
    return $sorted[[int](($sorted.Length - 1) / 2)]
}

function Get-TestResult($Results, $Matcher) {
    $Found = $Results -match $Matcher
    if ($Found) {
        return $Matches[1]
    } else {
        Write-Error "Error Processing Results:`n`n$Results"
    }
}

#region Throughput Publish

class ThroughputRequest {
    [string]$PlatformName;
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;

    ThroughputRequest (
        [TestRunDefinition]$Test
    ) {
        $this.PlatformName = $Test.ToTestPlatformString();
        $this.Loopback = $Test.Loopback;
        $this.Encryption = $Test.VariableValues["Encryption"] -eq "On";
        $this.SendBuffering = $Test.VariableValues["SendBuffering"] -eq "On";
        $this.NumberOfStreams = 1;
        $this.ServerToClient = $false;
    }
}

function Get-LatestThroughputRemoteTestResults([ThroughputRequest]$Request) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/throughput/get"
    $RequestJson = ConvertTo-Json -InputObject $Request
    Write-Debug "Requesting: $Uri with $RequestJson"
    $LatestResult = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Body $RequestJson -Method 'Post' -ContentType "application/json"
    Write-Debug "Result: $LatestResult"
    return $LatestResult
}

class ThroughputTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [string]$AuthKey;
    [double[]]$IndividualRunResults;
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;

    ThroughputTestPublishResult (
        [ThroughputRequest]$Request,
        [double[]]$RunResults,
        [string]$MachineName,
        [string]$CommitHash
    ) {
        $this.TestName = "Throughput"
        $this.MachineName = $MachineName
        $this.PlatformName = $Request.PlatformName
        $this.CommitHash = $CommitHash
        $this.AuthKey = "empty"
        $this.IndividualRunResults = $RunResults
        $this.Loopback = $Request.Loopback
        $this.Encryption = $Request.Encryption
        $this.SendBuffering = $Request.SendBuffering
        $this.NumberOfStreams = $Request.NumberOfStreams
        $this.ServerToClient = $Request.ServerToClient
    }
}

function Publish-ThroughputTestResults {
    param ([TestRunDefinition]$Test, $AllRunsResults, $CurrentCommitHash, $OutputDir)

    $Request = [ThroughputRequest]::new($Test)

    $MedianCurrentResult = Get-MedianTestResults -FullResults $AllRunsResults
    $FullLastResult = Get-LatestThroughputRemoteTestResults -Request $Request

    if ($FullLastResult -ne "") {
        $MedianLastResult = Get-MedianTestResults -FullResults $FullLastResult.individualRunResults
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        Write-Output "Median: $MedianCurrentResult $($Test.Units) ($PercentDiffStr%)"
        Write-Output "Master: $MedianLastResult $($Test.Units)"
    } else {
        Write-Output "Median: $MedianCurrentResult $($Test.Units)"
    }

    if ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Output "Saving results_$Test.json out for publishing."
        $MachineName = $null
        if (Test-Path 'env:AGENT_MACHINENAME') {
            $MachineName = $env:AGENT_MACHINENAME
        }
        $Results = [ThroughputTestPublishResult]::new($Request, $AllRunsResults, $MachineName, $CurrentCommitHash.Substring(0, 7))

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif (!$Publish) {
        Write-Debug "Failed to publish because of missing commit hash"
    }
}

#endregion

#region RPS Publish

class RPSRequest {
    [string]$PlatformName;
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;

    RPSRequest (
        [TestRunDefinition]$Test
    ) {
        $this.PlatformName = $Test.ToTestPlatformString();
        $this.ConnectionCount = $Test.VariableValues["ConnectionCount"];
        $this.RequestSize = $Test.VariableValues["RequestSize"];
        $this.ResponseSize = $Test.VariableValues["ResponseSize"];
        $this.ParallelRequests = 2;
    }
}

function Get-LatestRPSRemoteTestResults([RPSRequest]$Request) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/RPS/get"
    $RequestJson = ConvertTo-Json -InputObject $Request
    Write-Debug "Requesting: $Uri with $RequestJson"
    $LatestResult = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Body $RequestJson -Method 'Post' -ContentType "application/json"
    Write-Debug "Result: $LatestResult"
    return $LatestResult
}

class RPSTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [string]$AuthKey;
    [double[]]$IndividualRunResults;
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;

    RPSTestPublishResult (
        [RPSRequest]$Request,
        [double[]]$RunResults,
        [string]$MachineName,
        [string]$CommitHash
    ) {
        $this.TestName = "RPS"
        $this.MachineName = $MachineName
        $this.PlatformName = $Request.PlatformName
        $this.CommitHash = $CommitHash
        $this.AuthKey = "empty"
        $this.IndividualRunResults = $RunResults
        $this.ConnectionCount = $Request.ConnectionCount
        $this.RequestSize = $Request.RequestSize
        $this.ResponseSize = $Request.ResponseSize
        $this.ParallelRequests = $Request.ParallelRequests
    }
}

function Publish-RPSTestResults {
    param ([TestRunDefinition]$Test, $AllRunsResults, $CurrentCommitHash, $OutputDir)

    $Request = [RPSRequest]::new($Test)

    $MedianCurrentResult = Get-MedianTestResults -FullResults $AllRunsResults
    $FullLastResult = Get-LatestRPSRemoteTestResults -Request $Request

    if ($FullLastResult -ne "") {
        $MedianLastResult = Get-MedianTestResults -FullResults $FullLastResult.individualRunResults
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        Write-Output "Median: $MedianCurrentResult $($Test.Units) ($PercentDiffStr%)"
        Write-Output "Master: $MedianLastResult $($Test.Units)"
    } else {
        Write-Output "Median: $MedianCurrentResult $($Test.Units)"
    }

    if ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Output "Saving results_$Test.json out for publishing."
        $MachineName = $null
        if (Test-Path 'env:AGENT_MACHINENAME') {
            $MachineName = $env:AGENT_MACHINENAME
        }
        $Results = [RPSTestPublishResult]::new($Request, $AllRunsResults, $MachineName, $CurrentCommitHash.Substring(0, 7))

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif (!$Publish) {
        Write-Debug "Failed to publish because of missing commit hash"
    }
}

#endregion

#region HPS Publish

class HPSRequest {
    [string]$PlatformName;

    HPSRequest (
        [TestRunDefinition]$Test
    ) {
        $this.PlatformName = $Test.ToTestPlatformString();
    }
}

function Get-LatestHPSRemoteTestResults([HPSRequest]$Request) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/HPS/get"
    $RequestJson = ConvertTo-Json -InputObject $Request
    Write-Debug "Requesting: $Uri with $RequestJson"
    $LatestResult = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Body $RequestJson -Method 'Post' -ContentType "application/json"
    Write-Debug "Result: $LatestResult"
    return $LatestResult
}

class HPSTestPublishResult {
    [string]$MachineName;
    [string]$PlatformName;
    [string]$TestName;
    [string]$CommitHash;
    [string]$AuthKey;
    [double[]]$IndividualRunResults;

    HPSTestPublishResult (
        [HPSRequest]$Request,
        [double[]]$RunResults,
        [string]$MachineName,
        [string]$CommitHash
    ) {
        $this.TestName = "HPS"
        $this.MachineName = $MachineName
        $this.PlatformName = $Request.PlatformName
        $this.CommitHash = $CommitHash
        $this.AuthKey = "empty"
        $this.IndividualRunResults = $RunResults
    }
}

function Publish-HPSTestResults {
    param ([TestRunDefinition]$Test, $AllRunsResults, $CurrentCommitHash, $OutputDir)

    $Request = [HPSRequest]::new($Test)

    $MedianCurrentResult = Get-MedianTestResults -FullResults $AllRunsResults
    $FullLastResult = Get-LatestHPSRemoteTestResults -Request $Request

    if ($FullLastResult -ne "") {
        $MedianLastResult = Get-MedianTestResults -FullResults $FullLastResult.individualRunResults
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        Write-Output "Median: $MedianCurrentResult $($Test.Units) ($PercentDiffStr%)"
        Write-Output "Master: $MedianLastResult $($Test.Units)"
    } else {
        Write-Output "Median: $MedianCurrentResult $($Test.Units)"
    }

    if ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Output "Saving results_$Test.json out for publishing."
        $MachineName = $null
        if (Test-Path 'env:AGENT_MACHINENAME') {
            $MachineName = $env:AGENT_MACHINENAME
        }
        $Results = [HPSTestPublishResult]::new($Request, $AllRunsResults, $MachineName, $CurrentCommitHash.Substring(0, 7))

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif (!$Publish) {
        Write-Debug "Failed to publish because of missing commit hash"
    }
}

#endregion

function Publish-TestResults {
    param ([TestRunDefinition]$Test, $AllRunsResults, $CurrentCommitHash, $OutputDir)

    if ($Test.TestName -eq "Throughput") {
        Publish-ThroughputTestResults -Test $Test -AllRunsResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -OutputDir $OutputDir
    } elseif ($Test.TestName -eq "RPS") {
        Publish-RPSTestResults -Test $Test -AllRunsResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -OutputDir $OutputDir
    } elseif ($Test.TestName -eq "HPS") {
        Publish-HPSTestResults -Test $Test -AllRunsResults $AllRunsResults -CurrentCommitHash $CurrentCommitHash -OutputDir $OutputDir
    } else {
        Write-Host "Unknown Test Type"
    }
}

#region Test Parsing

class ExecutableRunSpec {
    [string]$Platform;
    [string]$Exe;
    [string[]]$Tls;
    [string[]]$Arch;
    [string]$Arguments;

    ExecutableRunSpec (
        [ExecutableSpec]$existingDef,
        [string]$arguments
    ) {
        $this.Platform = $existingDef.Platform
        $this.Exe = $existingDef.Exe
        $this.Tls = $existingDef.Tls
        $this.Arch = $existingDef.Arch
        $this.Arguments = $arguments
    }
}

class TestRunDefinition {
    [string]$TestName;
    [string]$VariableName;
    [string]$VariableValue;
    [ExecutableRunSpec]$Remote;
    [ExecutableRunSpec]$Local;
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;
    [hashtable]$VariableValues;
    [boolean]$Loopback;
    [boolean]$AllowLoopback;
    [string]$Units;

    TestRunDefinition (
        [TestDefinition]$existingDef,
        [string]$variableName,
        [string]$variableValue,
        [string]$localArgs,
        [string]$remoteArgs,
        [hashtable]$variableValues
    ) {
        $this.TestName = $existingDef.TestName
        $this.VariableName = $variableName
        $this.VariableValue = $variableValue
        $this.Local = [ExecutableRunSpec]::new($existingDef.Local, $localArgs)
        $this.Remote = [ExecutableRunSpec]::new($existingDef.Remote, $remoteArgs)
        $this.Iterations = $existingDef.Iterations
        $this.RemoteReadyMatcher = $existingDef.RemoteReadyMatcher
        $this.ResultsMatcher = $existingDef.ResultsMatcher
        $this.VariableValues = $variableValues
        $this.Loopback = $script:Local
        $this.AllowLoopback = $existingDef.AllowLoopback
        $this.Units = $existingDef.Units
    }

    TestRunDefinition (
        [TestDefinition]$existingDef,
        [string]$localArgs,
        [string]$remoteArgs,
        [hashtable]$variableValues
    ) {
        $this.TestName = $existingDef.TestName
        $this.VariableName = "Default"
        $this.VariableValue = ""
        $this.Local = [ExecutableRunSpec]::new($existingDef.Local, $localArgs)
        $this.Remote = [ExecutableRunSpec]::new($existingDef.Remote, $remoteArgs)
        $this.Iterations = $existingDef.Iterations
        $this.RemoteReadyMatcher = $existingDef.RemoteReadyMatcher
        $this.ResultsMatcher = $existingDef.ResultsMatcher
        $this.VariableValues = $variableValues
        $this.Loopback = $script:Local
        $this.AllowLoopback = $existingDef.AllowLoopback
        $this.Units = $existingDef.Units
    }

    [string]ToString() {
        $VarVal = "_$($this.VariableValue)"
        if ($this.VariableName -eq "Default") {
            $VarVal = ""
        }
        $Platform = $this.Remote.Platform
        if ($script:Kernel -and $this.Remote.Platform -eq "Windows") {
            $Platform = 'Winkernel'
        }
        $RetString = "$($this.TestName)_$($Platform)_$($script:RemoteArch)_$($script:RemoteTls)_$($this.VariableName)$VarVal"
        if ($this.Loopback) {
            $RetString += "_Loopback"
        }
        return $RetString
    }

    [string]ToTestPlatformString() {
        $Platform = $this.Remote.Platform
        if ($script:Kernel -and $this.Remote.Platform -eq "Windows") {
            $Platform = 'Winkernel'
        }
        $RetString = "$($Platform)_$($script:RemoteArch)_$($script:RemoteTls)"
        return $RetString
    }
}

class Defaults {
    [string]$LocalValue;
    [string]$RemoteValue;
    [string]$DefaultKey;

    Defaults (
        [string]$local,
        [string]$remote,
        [string]$defaultKey
    ) {
        $this.LocalValue = $local
        $this.RemoteValue = $remote
        $this.DefaultKey = $defaultKey
    }
}

function Get-TestMatrix {
    param ([TestDefinition[]]$Tests, $RemotePlatform, $LocalPlatform)

    [TestRunDefinition[]]$ToRunTests = @()

    foreach ($Test in $Tests) {

        if (!(Test-CanRunTest -Test $Test -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform)) {
            Write-Host "Skipping $($Test.ToString())"
            continue
        }

        [hashtable]$DefaultVals = @{}
        # Get all default variables
        foreach ($Var in $Test.Variables) {
            if ($Var.Local.Keys.Count -ne $Var.Remote.Keys.Count) {
                Write-Error "Remote and local key lengths must be the same"
            }
            $DefaultVals.Add($Var.Name, [Defaults]::new($Var.Local[$Var.Default], $Var.Remote[$Var.Default], $Var.Default))
        }

        $LocalArgs = $Test.Local.Arguments.All
        $RemoteArgs = $Test.Remote.Arguments.All

        if ($Local) {
            $LocalArgs += " " + $Test.Local.Arguments.Loopback
            $RemoteArgs += " " + $Test.Remote.Arguments.Loopback
        } else {
            $LocalArgs += " " + $Test.Local.Arguments.Remote
            $RemoteArgs += " " + $Test.Remote.Arguments.Remote
        }

        $DefaultLocalArgs = $LocalArgs
        $DefaultRemoteArgs = $RemoteArgs

        $VariableValues = @{}
        foreach ($VarKey in $DefaultVals.Keys) {
            $VariableValues.Add($VarKey, $DefaultVals[$VarKey].DefaultKey)
            $DefaultLocalArgs += (" " + $DefaultVals[$VarKey].LocalValue)
            $DefaultRemoteArgs += (" " + $DefaultVals[$VarKey].RemoteValue)
        }

        # Create the default test
        $TestRunDef = [TestRunDefinition]::new($Test, $DefaultLocalArgs, $DefaultRemoteArgs, $VariableValues)
        $ToRunTests += $TestRunDef

        foreach ($Var in $Test.Variables) {
            $LocalVarArgs = @{}
            $RemoteVarArgs = @{}

            $StateKeyList = @()

            foreach ($Key in $Var.Local.Keys) {
                $LocalVarArgs.Add($Key, $LocalArgs + " " + $Var.Local[$Key])
                $RemoteVarArgs.Add($Key, $RemoteArgs + " " + $Var.Remote[$Key])
                $StateKeyList += $Key
            }

            # Enumerate each variable, getting its value and the default
            foreach ($Key in $DefaultVals.Keys) {
                if ($Key -ne $Var.Name) {
                    foreach ($TestKey in $StateKeyList) {
                        $KeyVal =$DefaultVals[$Key]
                        $LocalVarArgs[$TestKey] += " $($KeyVal.LocalValue)"
                        $RemoteVarArgs[$TestKey] += " $($KeyVal.RemoteValue)"
                    }
                }
            }

            foreach ($Key in $StateKeyList) {
                $VariableValues = @{}
                foreach ($VarKey in $DefaultVals.Keys) {
                    $VariableValues.Add($VarKey, $DefaultVals[$VarKey].DefaultKey)
                }
                if ($VariableValues[$Var.Name] -eq $Key) {
                    continue
                }
                $VariableValues[$Var.Name] = $Key
                $TestRunDef = [TestRunDefinition]::new($Test, $Var.Name, $Key, $LocalVarArgs[$Key], $RemoteVarArgs[$Key], $VariableValues)
                $ToRunTests += $TestRunDef
            }
        }
    }

    return $ToRunTests
}

class ArgumentsSpec {
    [string]$All;
    [string]$Loopback;
    [string]$Remote;
}

class VariableSpec {
    [string]$Name;
    [Hashtable]$Local;
    [Hashtable]$Remote;
    [string]$Default;
}

class ExecutableSpec {
    [string]$Platform;
    [string[]]$Tls;
    [string[]]$Arch;
    [string]$Exe;
    [ArgumentsSpec]$Arguments;
}

class TestDefinition {
    [string]$TestName;
    [ExecutableSpec]$Remote;
    [ExecutableSpec]$Local;
    [VariableSpec[]]$Variables;
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;
    [boolean]$AllowLoopback;
    [string]$Units;

    [string]ToString() {
        $Platform = $this.Remote.Platform
        if ($script:Kernel -and $this.Remote.Platform -eq "Windows") {
            $Platform = 'Winkernel'
        }
        $RetString = "$($this.TestName)_$($Platform) [$($this.Remote.Arch)] [$($this.Remote.Tls)]"
        return $RetString
    }
}

function Get-Tests {
    param ($Path, $RemotePlatform, $LocalPlatform)
    $Tests = [TestDefinition[]](Get-Content -Path $Path | ConvertFrom-Json -AsHashtable)
    $MatrixTests = Get-TestMatrix -Tests $Tests -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform
    if (Test-AllTestsValid -Tests $MatrixTests) {
        return $MatrixTests
    } else {
        Write-Host "Error"
        return $null
    }
}

function Test-AllTestsValid {
    param ([TestRunDefinition[]]$Tests)

    $TestSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($T in $Tests) {
        if (!$TestSet.Add($T)) {
            return $false
        }
    }

    return $true
}

function Test-CanRunTest {
    param ([TestDefinition]$Test, $RemotePlatform, $LocalPlatform)
    $PlatformCorrect = ($Test.Local.Platform -eq $LocalPlatform) -and ($Test.Remote.Platform -eq $RemotePlatform)
    if (!$PlatformCorrect) {
        return $false
    }
    if (!$Test.Local.Tls.Contains($LocalTls)) {
        return $false
    }
    if (!$Test.Remote.Tls.Contains($RemoteTls)) {
        return $false
    }
    if ($Local -and !$Test.AllowLoopback) {
        return $false
    }
    return $true
}

#endregion

Export-ModuleMember -Function * -Alias *
