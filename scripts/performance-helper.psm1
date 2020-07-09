# Helper functions for msquic performance testing. As this is a module, this cannot be called directly.

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# WPA Profile for collecting stacks.
$WpaStackWalkProfileXml = `
@"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0" Author="MsQuic" Copyright="Microsoft Corporation" Company="Microsoft Corporation">
  <Profiles>
    <SystemCollector Id="SC_HighVolume" Realtime="false">
      <BufferSize Value="1024"/>
      <Buffers Value="20"/>
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

function Set-ScriptVariables {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param ($Local, $LocalTls, $LocalArch, $RemoteTls, $RemoteArch, $Config, $Publish, $Record)
    $script:Local = $Local
    $script:LocalTls = $LocalTls
    $script:LocalArch = $LocalArch
    $script:RemoteTls = $RemoteTls
    $script:RemoteArch = $RemoteArch
    $script:Config = $Config
    $script:Publish = $Publish
    $script:Record = $Record
}

function Set-Session {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param ($Session)
    $script:Session = $Session
    if ($null -ne $Session) {
        Invoke-Command -Session $Session -ScriptBlock {
            $ErrorActionPreference = "Stop"
        }
    }
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
    Wait-Job -Job $Job -Timeout 10 | Out-Null
    Stop-Job -Job $Job | Out-Null
    $RetVal = Receive-Job -Job $Job
    return $RetVal -join "`n"
}

function Copy-Artifacts {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    param ([string]$From, [string]$To)
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

class ArgumentsSpec {
    [string]$All;
    [string]$Loopback;
    [string]$Remote;

    [string]GetArguments() {
        if ($script:Local) {
            return "$($this.All) $($this.Loopback)"
        } else {
            return "$($this.All) $($this.Remote)"
        }
    }
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
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;

    [string]ToString() {
        $RetString = "$($this.TestName)_$($this.Remote.Platform)_$($script:RemoteArch)_$($script:RemoteTls)"
        if ($script:Local) {
            $RetString += "_Loopback"
        }
        return $RetString
    }

    [string]ToTestPlatformString() {
        $RetString = "$($this.Remote.Platform)_$($script:RemoteArch)_$($script:RemoteTls)"
        return $RetString
    }
}

class TestPublishResult {
    [string]$PlatformName
    [string]$TestName
    [string]$CommitHash
    [string]$MachineName
    [double[]]$IndividualRunResults
}

function Get-Tests {
    param ($Path)
    $Tests = [TestDefinition[]](Get-Content -Path $Path | ConvertFrom-Json)
    if (Test-AllTestsValid -Tests $Tests) {
        return $Tests
    } else {
        return $null
    }
}

function Test-AllTestsValid {
    param ([TestDefinition[]]$Tests)

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
    return $true
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

    Write-Debug "Running Remote: $Exe $RunArgs"

    return Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($Exe, $RunArgs, $BasePath, $Record, $WpaStackWalkProfileXml)
        if ($null -ne $BasePath) {
            $env:LD_LIBRARY_PATH = $BasePath
        }

        if ($Record -and $IsWindows) {
            $EtwXmlName = $Exe + ".remote.wprp"
            wpr.exe -cancel 2> $null

            $WpaStackWalkProfileXml | Out-File $EtwXmlName
            wpr.exe -start $EtwXmlName -filemode 2> $null
        }

        & $Exe ($RunArgs).Split(" ")

        if ($Record -and $IsWindows) {
            $EtwName = $Exe + ".remote.etl"
            wpr.exe -stop $EtwName 2> $null
        }
    } -AsJob -ArgumentList $Exe, $RunArgs, $BasePath, $Record, $WpaStackWalkProfileXml
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

    $LocalJob = Start-Job -ScriptBlock { & $Using:Exe ($Using:RunArgs).Split(" ") }

    # Wait 60 seconds for the job to finish
    Wait-Job -Job $LocalJob -Timeout $Timeout | Out-Null
    Stop-Job -Job $LocalJob | Out-Null

    $RetVal = Receive-Job -Job $LocalJob
    return $RetVal -join "`n"
}

function Get-LatestRemoteTestResults($Platform, $Test) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/performance/$Platform/$Test"
    Write-Debug "Requesting: $Uri"
    $LatestResult = Invoke-RestMethod -Uri $Uri
    Write-Debug "Result: $LatestResult"
    return $LatestResult
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

function Publish-TestResults {
    param ([TestDefinition]$Test, $AllRunsResults, $CurrentCommitHash, $OutputDir)
    $Platform = $Test.ToTestPlatformString()
    $TestName = $Test.TestName
    if ($Local) {
        $TestName += "_Loopback"
    }

    # Print current and latest master results to console.
    $MedianCurrentResult = Get-MedianTestResults -FullResults $AllRunsResults
    $fullLastResult = Get-LatestRemoteTestResults -Platform $Platform -Test $TestName
    if ($fullLastResult -ne "") {
        $MedianLastResult = Get-MedianTestResults -FullResults $fullLastResult.individualRunResults
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        Write-Output "Median: $MedianCurrentResult kbps ($PercentDiffStr%)"
        Write-Output "Master: $MedianLastResult kbps"
    } else {
        Write-Output "Median: $MedianCurrentResult kbps"
    }

    if ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Output "Saving results_$Test.json out for publishing."
        $Results = [TestPublishResult]::new()
        $Results.CommitHash = $CurrentCommitHash.Substring(0, 7)
        $Results.PlatformName = $Platform
        $Results.TestName = $TestName
        $Results.MachineName = $null
        if (Test-Path 'env:AGENT_MACHINENAME') {
            $Results.MachineName = $env:AGENT_MACHINENAME
        }
        $Results.IndividualRunResults = $AllRunsResults

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif ($Publish -and ($null -ne $CurrentCommitHash)) {
        Write-Debug "Failed to publish because of missing commit hash"
    }
}

function Merge-PGOCounts {
    param ($Path, $OutputDir)
    $Command = "$Path\pgomgr.exe /merge $Path $Path\msquic.pgd"
    Invoke-Expression $Command | Write-Debug
    Remove-Item "$Path\*.pgc" | Out-Null
}

Export-ModuleMember -Function * -Alias *
