<#

.SYNOPSIS
This script runs performance tests with various emulated network conditions. Note,
this script requires duonic to be preinstalled on the system and quicperf.exe to
be in the current directory.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.PARAMETER RttMs
    The round trip time(s) for the emulated network.

.PARAMETER BottleneckMbps
    The maximum rate(s) for the emulated network.

.PARAMETER BottleneckQueueRatio
    The queue length as a ratio of BDP for the emulated network.

.PARAMETER RandomLossDenominator
    For N > 0, indicates a random drop chance of 1 / N packets in the emulated network.
    For N <= 0, indicates no random loss/drops in the emulated network.

.PARAMETER RandomReorderDenominator
    For N > 0, indicates a random delay chance of 1 / N packets in the emulated network.
    For N <= 0, indicates no random reordering in the emulated network.

.PARAMETER ReorderDelayDeltaMs
    The extra delay applied to any reordered packets in the emulated network.

.PARAMETER DurationMs
    The duration(s) of each test run over the emulated network.

.PARAMETER Pacing
    The pacing enabled/disable flag(s) used for each test run over the emulated network.

.PARAMETER NumIterations
    The number(s) of iterations to run of each test over the emulated network.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [string[]]$Protocol = "QUIC",

    [Parameter(Mandatory = $false)]
    [Int32[]]$RttMs = 60,

    [Parameter(Mandatory = $false)]
    [Int32[]]$BottleneckMbps = 20,

    [Parameter(Mandatory = $false)]
    [double[]]$BottleneckQueueRatio = 1.0,

    [Parameter(Mandatory = $false)]
    [Int32[]]$RandomLossDenominator = 0,

    [Parameter(Mandatory = $false)]
    [Int32[]]$RandomReorderDenominator = 0,

    [Parameter(Mandatory = $false)]
    [Int32[]]$ReorderDelayDeltaMs = 0,

    [Parameter(Mandatory = $false)]
    [Int32[]]$DurationMs = 10000,

    [Parameter(Mandatory = $false)]
    [Int32[]]$Pacing = (0, 1),

    [Parameter(Mandatory = $false)]
    [Int32]$NumIterations = 1,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Datapath.Light", "Datapath.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$Periodic = $false,

    [Parameter(Mandatory = $false)]
    [string]$ForceBranchName = $null
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

class TestResult {
    [int]$RttMs;
    [int]$BottleneckMbps;
    [int]$BottleneckBufferPackets;
    [int]$RandomLossDenominator;
    [int]$RandomReorderDenominator;
    [int]$ReorderDelayDeltaMs;
    [bool]$Tcp;
    [int]$DurationMs;
    [bool]$Pacing;
    [int]$RateKbps;
    [System.Collections.Generic.List[int]]$RawRateKbps;

    TestResult (
        [int]$RttMs,
        [int]$BottleneckMbps,
        [int]$BottleneckBufferPackets,
        [int]$RandomLossDenominator,
        [int]$RandomReorderDenominator,
        [int]$ReorderDelayDeltaMs,
        [bool]$Tcp,
        [int]$DurationMs,
        [bool]$Pacing,
        [int]$RateKbps,
        [System.Collections.Generic.List[int]]$RawRateKbps
    ) {
        $this.RttMs = $RttMs;
        $this.BottleneckMbps = $BottleneckMbps;
        $this.BottleneckBufferPackets = $BottleneckBufferPackets;
        $this.RandomLossDenominator = $RandomLossDenominator;
        $this.RandomReorderDenominator = $RandomReorderDenominator;
        $this.ReorderDelayDeltaMs = $ReorderDelayDeltaMs;
        $this.Tcp = $Tcp;
        $this.DurationMs = $DurationMs;
        $this.Pacing = $Pacing;
        $this.RateKbps = $RateKbps;
        $this.RawRateKbps = $RawRateKbps;
    }
}

class Results {
    [System.Collections.Generic.List[TestResult]]$Runs;
    [string]$PlatformName

    Results($PlatformName) {
        $this.Runs = [System.Collections.Generic.List[TestResult]]::new()
        $this.PlatformName = $PlatformName
    }
}

function Find-MatchingTest([TestResult]$TestResult, [Object]$RemoteResults) {
    foreach ($Remote in $RemoteResults) {
        if (
            $TestResult.RttMs -eq $Remote.RttMs -and
            $TestResult.BottleneckMbps -eq $Remote.BottleneckMbps -and
            $TestResult.BottleneckBufferPackets -eq $Remote.BottleneckBufferPackets -and
            $TestResult.RandomLossDenominator -eq $Remote.RandomLossDenominator -and
            $TestResult.RandomReorderDenominator -eq $Remote.RandomReorderDenominator -and
            $TestResult.ReorderDelayDeltaMs -eq $Remote.ReorderDelayDeltaMs -and
            $TestResult.Tcp -eq $Remote.Tcp -and
            $TestResult.DurationMs -eq $Remote.DurationMs -and
            $TestResult.Pacing -eq $Remote.Pacing
        ) {
            return $Remote
        }
    }
    return $null;
}

function Get-CurrentBranch {
    param($RepoDir)
    $CurrentLoc = Get-Location
    Set-Location -Path $RepoDir | Out-Null
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentBranch = $null
    try {
        $CurrentBranch = git branch --show-current
    } catch {
        Write-Debug "Failed to get commit date from git"
    }
    Set-Location -Path $CurrentLoc | Out-Null
    return $CurrentBranch
}

function Get-LatestCommitHash([string]$Branch) {
    $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/data/$Branch/commits.json"
    if ($Periodic) {
        $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/periodic/$Branch/commits.json"
    }
    Write-Debug "Requesting: $Uri"
    try {
        $AllCommits = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Method 'GET' -ContentType "application/json"
        Write-Debug "Result: $AllCommits"
        $LatestResult = ($AllCommits | Sort-Object -Property Date -Descending)[0]
        Write-Debug "Latest Commit: $LatestResult"
        if ($Periodic) {
            return $LatestResult.Date
        } else {
            return $LatestResult.CommitHash
        }
    } catch {
        return ""
    }
}

function Get-LatestWanTestResult([string]$Branch, [string]$CommitHash) {
    $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/data/$Branch/$CommitHash/wan_data.json"
    if ($Periodic) {
        $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/periodic/$Branch/$CommitHash/wan_data.json"
    }
    Write-Debug "Requesting: $Uri"
    try {
        $LatestResult = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Method 'GET' -ContentType "application/json"
        Write-Debug "Result: $LatestResult"
        return $LatestResult
    } catch {
        return ""
    }
}

# See if we are an AZP PR
$PrBranchName = $env:SYSTEM_PULLREQUEST_TARGETBRANCH
if ([string]::IsNullOrWhiteSpace($PrBranchName)) {
    # Mainline build, just get branch name
    $AzpBranchName = $env:BUILD_SOURCEBRANCH
    if ([string]::IsNullOrWhiteSpace($AzpBranchName)) {
        # Non azure build
        $BranchName = Get-CurrentBranch -RepoDir $RootDir
    } else {
        # Azure Build
        $BranchName = $AzpBranchName.Substring(11);
    }
} else {
    # PR Build
    $BranchName = $PrBranchName
}

if (![string]::IsNullOrWhiteSpace($ForceBranchName)) {
    $BranchName = $ForceBranchName
}

$LastCommitHash = Get-LatestCommitHash -Branch $BranchName
$PreviousResults = Get-LatestWanTestResult -Branch $BranchName -CommitHash $LastCommitHash

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Script for controlling loggings.
$LogScript = Join-Path $RootDir "scripts" "log.ps1"

# Folder for log files.
$LogDir = Join-Path $RootDir "artifacts" "logs" "wanperf" (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')
if ($LogProfile -ne "None") {
    try {
        Write-Debug "Canceling any already running logs"
        & $LogScript -Cancel
    } catch {
    }
    New-Item -Path $LogDir -ItemType Directory -Force | Write-Debug
    Get-ChildItem $LogScript | Write-Debug
}

$Platform = $IsWindows ? "windows" : "linux"
$PlatformName = (($IsWindows ? "Windows" : "Linux") + "_$($Arch)_$($Tls)")

# Path to the quicperf exectuable.
$ExeName = $IsWindows ? "quicperf.exe" : "quicperf"
$QuicPerf = Join-Path $RootDir "artifacts" "bin" $Platform "$($Arch)_$($Config)_$($Tls)" $ExeName

Get-NetAdapter | Write-Debug
ipconfig -all | Write-Debug

# Make sure to kill any old processes
try { Stop-Process -Name quicperf } catch { }

# Start the perf server listening.
Write-Debug "Starting server..."
if (!(Test-Path -Path $QuicPerf)) {
    Write-Error "Missing file: $QuicPerf"
}
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $QuicPerf
$pinfo.UseShellExecute = $false
$pinfo.RedirectStandardOutput = $true
$pinfo.RedirectStandardError = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$p.Start() | Out-Null

# Wait for the server(s) to come up.
Start-Sleep -Seconds 1

$OutputDir = Join-Path $RootDir "artifacts" "PerfDataResults" $Platform "$($Arch)_$($Config)_$($Tls)" "WAN"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
$UniqueId = New-Guid
$OutputFile = Join-Path $OutputDir "WANPerf_$($UniqueId.ToString("N")).json"
# CSV header
$Header = "RttMs, BottleneckMbps, BottleneckBufferPackets, RandomLossDenominator, RandomReorderDenominator, ReorderDelayDeltaMs, Tcp, DurationMs, Pacing, RateKbps"
for ($i = 0; $i -lt $NumIterations; $i++) {
    $Header += ", RawRateKbps$($i+1)"
}
Write-Host $Header

# Turn on RDQ for duonic.
Set-NetAdapterAdvancedProperty duo? -DisplayName RdqEnabled -RegistryValue 1 -NoRestart

# The RDQ buffer limit is by packets and not bytes, so turn off LSO to avoid
# strange behavior. This makes RDQ behave more like a real middlebox on the
# network (such a middlebox would only see packets after LSO sends are split
# into MTU-sized packets).
Set-NetAdapterLso duo? -IPv4Enabled $false -IPv6Enabled $false -NoRestart

$RunResults = [Results]::new($PlatformName)

$RemoteResults = $PreviousResults.$PlatformName

# Loop over all the network emulation configurations.
foreach ($ThisRttMs in $RttMs) {
foreach ($ThisBottleneckMbps in $BottleneckMbps) {
foreach ($ThisBottleneckQueueRatio in $BottleneckQueueRatio) {
foreach ($ThisRandomLossDenominator in $RandomLossDenominator) {
foreach ($ThisRandomReorderDenominator in $RandomReorderDenominator) {
foreach ($ThisReorderDelayDeltaMs in $ReorderDelayDeltaMs) {

    if (($ThisRandomReorderDenominator -ne 0) -ne ($ThisReorderDelayDeltaMs -ne 0)) {
        continue; # Ignore cases where one is zero, but the other isn't.
    }

    # Calculate BDP in 'packets'
    $BDP = [double]($ThisRttMs * $ThisBottleneckMbps) / (1.5 * 8.0)
    $ThisBottleneckBufferPackets = [int]($BDP * $ThisBottleneckQueueRatio * 1.1)

    # Configure duonic for the desired network emulation options.
    Write-Debug "Configure NIC: Rtt=$ThisRttMs ms, Bottneck=[$ThisBottleneckMbps mbps, $ThisBottleneckBufferPackets packets], RandomLoss=1/$ThisRandomLossDenominator, ReorderDelayDelta=$ThisReorderDelayDeltaMs ms, RandomReorder=1/$ThisRandomReorderDenominator"
    $DelayMs = [convert]::ToInt32([int]($ThisRttMs)/2)
    Set-NetAdapterAdvancedProperty duo? -DisplayName DelayMs -RegistryValue $DelayMs -NoRestart
    Set-NetAdapterAdvancedProperty duo? -DisplayName RateLimitMbps -RegistryValue $ThisBottleneckMbps -NoRestart
    Set-NetAdapterAdvancedProperty duo? -DisplayName QueueLimitPackets -RegistryValue $ThisBottleneckBufferPackets -NoRestart
    Set-NetAdapterAdvancedProperty duo? -DisplayName RandomLossDenominator -RegistryValue $ThisRandomLossDenominator -NoRestart
    Set-NetAdapterAdvancedProperty duo? -DisplayName RandomReorderDenominator -RegistryValue $ThisRandomReorderDenominator -NoRestart
    Set-NetAdapterAdvancedProperty duo? -DisplayName ReorderDelayDeltaMs -RegistryValue $ThisReorderDelayDeltaMs -NoRestart
    Write-Debug "Restarting NIC"
    Restart-NetAdapter duo?
    Start-Sleep 5 # (wait for duonic to restart)

    # Loop over all the test configurations.
    foreach ($ThisProtocol in $Protocol) {
    foreach ($ThisDurationMs in $DurationMs) {
    foreach ($ThisPacing in $Pacing) {

        $UseTcp = 0
        if ($ThisProtocol -eq "TCPTLS") {
            $UseTcp = 1
        }

        $MaxRuntimeMs = $ThisDurationMs + 5000

        # Run through all the iterations and keep track of the results.
        $Results = [System.Collections.Generic.List[int]]::new()
        Write-Debug "Run upload test: Duration=$ThisDurationMs ms, Pacing=$ThisPacing"
        for ($i = 0; $i -lt $NumIterations; $i++) {

            if ($LogProfile -ne "None") {
                try {
                    & $LogScript -Start -Profile $LogProfile | Out-Null
                } catch {
                    Write-Debug "Logging exception"
                }
            }

            # Run the throughput upload test with the current configuration.
            Write-Debug "Run upload test: Iteration=$($i + 1)"

            $Rate = 0
            $Command = "$QuicPerf -test:tput -tcp:$UseTcp -maxruntime:$MaxRuntimeMs -bind:192.168.1.12 -target:192.168.1.11 -sendbuf:0 -upload:$ThisDurationMs -timed:1 -pacing:$ThisPacing"
            Write-Debug $Command
            $Output = [string](Invoke-Expression $Command)
            Write-Debug $Output
            if (!$Output.Contains("App Main returning status 0") -or $Output.Contains("Error:")) {
                # Don't treat one failure as fatal for the whole run. Just print
                # it out, use 0 as the rate, and continue on.
                Write-Host $Command
                Write-Host $Output
                $Rate = 0

            } else {
                # Grab the rate from the output text. Example:
                #   Started!  Result: 23068672 bytes @ 18066 kbps (10215.203 ms). App Main returning status 0
                $Rate = [int]$Output.Split(" ")[6]
                Write-Debug "$Rate Kbps"
            }

            $Results.Add($Rate) | Out-Null

            if ($LogProfile -ne "None") {
                $TestLogPath = Join-Path $LogDir "$ThisRttMs.$ThisBottleneckMbps.$ThisBottleneckBufferPackets.$ThisRandomLossDenominator.$ThisRandomReorderDenominator.$ThisReorderDelayDeltaMs.$UseTcp.$ThisDurationMs.$ThisPacing.$i.$Rate"
                try {
                    & $LogScript -Stop -OutputPath $TestLogPath -RawLogOnly | Out-Null
                } catch {
                    Write-Debug "Logging exception"
                }
            }
        }

        # Grab the average result and write the CSV output.
        $RateKbps = [int]($Results | Where-Object {$_ -ne 0} | Measure-Object -Average).Average
        $Row = "$ThisRttMs, $ThisBottleneckMbps, $ThisBottleneckBufferPackets, $ThisRandomLossDenominator, $ThisRandomReorderDenominator, $ThisReorderDelayDeltaMs, $UseTcp, $ThisDurationMs, $ThisPacing, $RateKbps"
        for ($i = 0; $i -lt $NumIterations; $i++) {
            $Row += ", $($Results[$i])"
        }
        $RunResult = [TestResult]::new($ThisRttMs, $ThisBottleneckMbps, $ThisBottleneckBufferPackets, $ThisRandomLossDenominator, $ThisRandomReorderDenominator, $ThisReorderDelayDeltaMs, $UseTcp, $ThisDurationMs, $ThisPacing, $RateKbps, $Results);
        $RunResults.Runs.Add($RunResult)
        Write-Host $Row
        $RemoteResult = Find-MatchingTest -TestResult $RunResult -RemoteResults $RemoteResults
        if ($null -ne $RemoteResult) {
            $MedianLastResult = $RemoteResult.RateKbps
            $PercentDiff = 100 * (($RateKbps - $MedianLastResult) / $MedianLastResult)
            $PercentDiffStr = $PercentDiff.ToString("#.##")
            if ($PercentDiff -ge 0) {
                $PercentDiffStr = "+$PercentDiffStr"
            }
            Write-Output "Median: $RateKbps, Remote: $MedianLastResult, ($PercentDiffStr%)"
        }
    }}}

}}}}}}

$RunResults | ConvertTo-Json -Depth 100 | Out-File $OutputFile

# Kill any leftovers.
try { Stop-Process -Name quicperf } catch { }
