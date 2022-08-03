<#

.SYNOPSIS
This script runs performance tests with various emulated network conditions. Note,
this script requires duonic to be preinstalled on the system and secnetperf.exe to
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

.PARAMETER BaseRandomSeed
    Base seed value for the DuoNic RNG.

.PARAMETER DurationMs
    The duration(s) of each test run over the emulated network.

.PARAMETER Pacing
    The pacing enabled/disable flag(s) used for each test run over the emulated network.

.PARAMETER NumIterations
    The number(s) of iterations to run of each test over the emulated network.

.PARAMETER MergeDataFiles
    Merges the data files from multiple parallel runs into a combined file.

.PARAMETER NoDateLogDir
    Doesn't include the Date/Time in the log directory path.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
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
    [string]$BaseRandomSeed = "",

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
    [string]$ForceBranchName = $null,

    [Parameter(Mandatory = $false)]
    [switch]$MergeDataFiles = $false,

    [Parameter(Mandatory = $false)]
    [switch]$NoDateLogDir = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

class FormattedResult {
    [double]$Usage;
    [double]$DiffPrev;
    [int]$NetMbps;
    [int]$RttMs;
    [int]$QueuePkts;
    [int]$Loss;
    [int]$Reorder;
    [int]$DelayMs;
    #[int]$DurationMs;
    #[bool]$Pacing;
    [int]$RateKbps;
    [int]$PrevKbps;
    [int]$Tcp;

    FormattedResult (
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
        [int]$RemoteKbps
    ) {
        $this.Tcp = $Tcp;
        $this.RttMs = $RttMs;
        $this.NetMbps = $BottleneckMbps;
        $this.QueuePkts = $BottleneckBufferPackets;
        $this.Loss = $RandomLossDenominator;
        $this.Reorder = $RandomReorderDenominator;
        $this.DelayMs = $ReorderDelayDeltaMs;
        #$this.DurationMs = $DurationMs;
        #$this.Pacing = $Pacing;
        $this.RateKbps = $RateKbps;
        $this.PrevKbps = $RemoteKbps;

        $this.Usage = ($RateKbps / $BottleneckMbps) / 10;
        $this.DiffPrev = (($RateKbps - $RemoteKbps) / $BottleneckMbps) / 10;
    }
}

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

function Find-MatchingTest([Object]$TestResult, [Object]$RemoteResults) {
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

function Get-CurrentBranch([string]$RepoDir) {
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

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

$Platform = $IsWindows ? "windows" : "linux"
$PlatformName = (($IsWindows ? "Windows" : "Linux") + "_$($Arch)_$($Tls)")
$CommitMergedData = $false

if (![string]::IsNullOrWhiteSpace($ForceBranchName)) {
    # Forcing a specific branch.
    $BranchName = $ForceBranchName

} elseif (![string]::IsNullOrWhiteSpace($env:SYSTEM_PULLREQUEST_TARGETBRANCH)) {
    # We are in a (AZP) pull request build.
    Write-Host "Using SYSTEM_PULLREQUEST_TARGETBRANCH=$env:SYSTEM_PULLREQUEST_TARGETBRANCH to compute branch"
    $BranchName = $env:SYSTEM_PULLREQUEST_TARGETBRANCH

} elseif (![string]::IsNullOrWhiteSpace($env:GITHUB_BASE_REF)) {
    # We are in a (GitHub Action) pull request build.
    Write-Host "Using GITHUB_BASE_REF=$env:GITHUB_BASE_REF to compute branch"
    $BranchName = $env:GITHUB_BASE_REF

} elseif (![string]::IsNullOrWhiteSpace($env:BUILD_SOURCEBRANCH)) {
    # We are in a (AZP) main build.
    Write-Host "Using BUILD_SOURCEBRANCH=$env:BUILD_SOURCEBRANCH to compute branch"
    $BranchName = $env:BUILD_SOURCEBRANCH.Substring(11)

} elseif (![string]::IsNullOrWhiteSpace($env:GITHUB_REF_NAME)) {
    # We are in a (GitHub Action) main build.
    Write-Host "Using GITHUB_REF_NAME=$env:GITHUB_REF_NAME to compute branch"
    $BranchName = $env:GITHUB_REF_NAME
    $CommitMergedData = $true

} else {
    # Fallback to the current branch.
    $BranchName = Get-CurrentBranch -RepoDir $RootDir
}

if (![string]::IsNullOrWhiteSpace($ForceBranchName)) {
    $BranchName = $ForceBranchName
}

Write-Debug "Branch: $BranchName"

$LastCommitHash = Get-LatestCommitHash -Branch $BranchName
$PreviousResults = Get-LatestWanTestResult -Branch $BranchName -CommitHash $LastCommitHash

Write-Debug "LastCommitHash: $LastCommitHash"

$RemoteResults = ""
if ($PreviousResults -ne "") {
    try {
        $RemoteResults = $PreviousResults.$PlatformName
    } catch {
        Write-Debug "Failed to get $PlatformName from previous results"
    }
}

# Path to the output data.
$OutputDir = Join-Path $RootDir "artifacts" "PerfDataResults" $Platform "$($Arch)_$($Config)_$($Tls)" "WAN"

if ($MergeDataFiles) {
    $OutputResults = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new()
    $FormatResults = [System.Collections.Generic.List[FormattedResult]]::new()

    # Load all json files in the output directory.
    $DataFiles = Get-ChildItem -Path $OutputDir -Filter "*.json"
    $DataFiles | ForEach-Object {
        $Data = Get-Content $_ | ConvertFrom-Json

        # Convert the data to the proper output format.
        $RunList = $null;
        if ($OutputResults.TryGetValue($Data.PlatformName, [ref]$RunList)) {
            $RunList.AddRange($Data.Runs);
        } else {
            $RunList = [System.Collections.Generic.List[object]]::new($Data.Runs)
            $OutputResults.Add($Data.PlatformName, $RunList);
        }

        # Convert the data to a better format for printing to console.
        $Data.Runs | ForEach-Object {

            $RemoteRate = 0
            if ($RemoteResults -ne "") {
                $RemoteResult = Find-MatchingTest -TestResult $_ -RemoteResults $RemoteResults
                if ($null -ne $RemoteResult) {
                    $RemoteRate = $RemoteResult.RateKbps
                }
            }

            $Run = [FormattedResult]::new($_.RttMs, $_.BottleneckMbps, $_.BottleneckBufferPackets, $_.RandomLossDenominator, $_.RandomReorderDenominator, $_.ReorderDelayDeltaMs, $_.Tcp, $_.DurationMs, $_.Pacing, $_.RateKbps, $RemoteRate);
            $FormatResults.Add($Run)
        }
    }

    if ($CommitMergedData) {
        $env:GIT_REDIRECT_STDERR = '2>&1'
        # Cache the current commit hash (before changing branches).
        $CurCommitHash = git rev-parse --short HEAD
        $CurCommitHash = $CurCommitHash.Substring(0,7)

        Write-Debug "CurCommitHash: $CurCommitHash"

        # Checkout the performance branch (where data is stored).
        git checkout performance

        # Ensure the output directory exists.
        $DataFolder = Join-Path $RootDir "data" $BranchName $CurCommitHash
        New-Item -Path $DataFolder -ItemType "directory" -Force | Out-Null

        # Write the output file.
        $OutputString = $OutputResults | ConvertTo-Json -Depth 100
        $OutputFile = Join-Path $DataFolder "wan_data.json"
        Out-File -FilePath $OutputFile -InputObject $OutputString -Force

        # Commit the output file.
        git config user.email "quicdev@microsoft.com"
        git config user.name "QUIC Dev[bot]"
        git add .
        git status
        git commit -m "Commit WAN Perf Results for $CurCommitHash"
        git pull
        git push

        # Revert back to the branch.
        git checkout $BranchName
    }

    # Show the worst absolute tests.
    Write-Host "`nWorst tests, relative to bottleneck rate (Usage):"
    $FormatResults | Sort-Object -Property Usage | Select-Object -First 50 | Format-Table -AutoSize *

    # Show the worst tests, relative to the previous run.
    Write-Host "Worst tests, relative to the previous run (DiffPrev):"
    $FormatResults | Sort-Object -Property DiffPrev | Select-Object -First 50 | Format-Table -AutoSize *

    # Dump all data.
    Write-Host "All tests:"
    $FormatResults | Sort-Object -Property Tcp,NetMbps,RttMs,QueuePkts,Loss,Reorder,DelayMs | Format-Table -AutoSize *

    # Write all data to CSV.
    $CsvFile = Join-Path $OutputDir "wan_data.csv"
    Write-Host "Writing all data to $CsvFile"
    $FormatResults | Sort-Object -Property Tcp,NetMbps,RttMs,QueuePkts,Loss,Reorder,DelayMs | `
        Export-Csv -Path $CsvFile -NoTypeInformation -Force -UseQuotes AsNeeded

    return
}

# Script for controlling loggings.
$LogScript = Join-Path $RootDir "scripts" "log.ps1"

# Folder for log files.
$LogDir = Join-Path $RootDir "artifacts" "logs" "wanperf"
if (!$NoDateLogDir) {
    $LogDir = Join-Path $LogDir (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')
}
if ($LogProfile -ne "None") {
    try {
        Write-Debug "Canceling any already running logs"
        & $LogScript -Cancel | Out-Null
    } catch {
    }
    New-Item -Path $LogDir -ItemType Directory -Force | Write-Debug
    Get-ChildItem $LogScript | Write-Debug
    Write-Host "Logging to $LogDir"
}

if ($BaseRandomSeed -eq "") {
    for ($i = 0; $i -lt 3; $i++) {
        $BaseRandomSeed += $(Get-Random).ToString('x8')
    }
    $BaseRandomSeed += $(Get-Random).ToString('x8').Substring(0,6)
    # This gives 15 bytes of random seed, and the last byte will be
    # the iteration count.
}

Write-Host "BaseRandomSeed: $($BaseRandomSeed)"

# Path to the secnetperf exectuable.
$ExeName = $IsWindows ? "secnetperf.exe" : "secnetperf"
$SecNetPerf = Join-Path $RootDir "artifacts" "bin" $Platform "$($Arch)_$($Config)_$($Tls)" $ExeName

# Make sure to kill any old processes
try { Stop-Process -Name secnetperf } catch { }

# Start the perf server listening.
Write-Debug "Starting server..."
if (!(Test-Path -Path $SecNetPerf)) {
    Write-Error "Missing file: $SecNetPerf"
}
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $SecNetPerf
$pinfo.UseShellExecute = $false
$pinfo.RedirectStandardOutput = $true
$pinfo.RedirectStandardError = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$p.Start() | Out-Null

# Wait for the server(s) to come up.
Start-Sleep -Seconds 1

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

# Configure duonic ring buffer size to be 4096 (2^12).
Set-NetAdapterAdvancedProperty duo? -DisplayName TxQueueSizeExp -RegistryValue 13 -NoRestart
Set-NetAdapterAdvancedProperty duo? -DisplayName RxQueueSizeExp -RegistryValue 13 -NoRestart

# The RDQ buffer limit is by packets and not bytes, so turn off LSO to avoid
# strange behavior. This makes RDQ behave more like a real middlebox on the
# network (such a middlebox would only see packets after LSO sends are split
# into MTU-sized packets).
Set-NetAdapterLso duo? -IPv4Enabled $false -IPv6Enabled $false -NoRestart

$RunResults = [Results]::new($PlatformName)

# Add pktmon filter to track packet loss.
pktmon filter add -t UDP -p 4433

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

            $RandomSeed = $BaseRandomSeed + $i.ToString('x2').Substring(0,2)
            Set-NetAdapterAdvancedProperty duo? -DisplayName RandomSeed -RegistryValue $RandomSeed -NoRestart

            Write-Debug "Restarting NIC"
            $TryCount = 0
            $Success = $false
            while ($TryCount -lt 3) {
                try {
                    Restart-NetAdapter duo?
                    $Success = $true
                    break
                } catch {
                    $TryCount++
                    Write-Debug "Exception while restarting NIC. Trying Again."
                    Start-Sleep -Seconds 1
                }
            }
            if (!$Success) {
                Write-Error "Failed to restart NIC after 3 tries."
            }
            Start-Sleep 5 # (wait for duonic to restart)

            if ($LogProfile -ne "None") {
                try {
                    & $LogScript -Start -Profile $LogProfile | Out-Null
                } catch {
                    Write-Debug "Logging exception"
                }
            }

            # Run the throughput upload test with the current configuration.
            Write-Debug "Run upload test: Iteration=$($i + 1)"

            # Start pktmon capture.
            pktmon start --capture --counters-only

            $Rate = 0
            $Command = "$SecNetPerf -test:tput -tcp:$UseTcp -maxruntime:$MaxRuntimeMs -bind:192.168.1.12 -target:192.168.1.11 -sendbuf:0 -upload:$ThisDurationMs -timed:1 -pacing:$ThisPacing"
            Write-Debug $Command
            $Output = [string](Invoke-Expression $Command)
            Write-Debug $Output
            if (!$Output.Contains("App Main returning status 0") -or $Output.Contains("Error:") -or $Output.Contains("@ 0 kbps")) {
                # Don't treat one failure as fatal for the whole run. Just print
                # it out, use 0 as the rate, and continue on.
                Write-Host $Command
                Write-Warning $Output
                $Rate = 0

            } else {
                # Grab the rate from the output text. Example:
                #   Started!  Result: 23068672 bytes @ 18066 kbps (10215.203 ms). App Main returning status 0
                $Rate = [int]$Output.Split(" ")[6]
                Write-Debug "$Rate Kbps"
            }

            $Results.Add($Rate) | Out-Null

            Write-Debug (Out-String -InputObject (Invoke-Expression "pktmon stop"))

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
        $RateKbps = [int]($Results | Where-Object {$_ -ne 0} | Measure-Object -Average).Average # TODO - Convert to Median instead of Average
        $Row = "$ThisRttMs, $ThisBottleneckMbps, $ThisBottleneckBufferPackets, $ThisRandomLossDenominator, $ThisRandomReorderDenominator, $ThisReorderDelayDeltaMs, $UseTcp, $ThisDurationMs, $ThisPacing, $RateKbps"
        for ($i = 0; $i -lt $NumIterations; $i++) {
            $Row += ", $($Results[$i])"
        }
        $RunResult = [TestResult]::new($ThisRttMs, $ThisBottleneckMbps, $ThisBottleneckBufferPackets, $ThisRandomLossDenominator, $ThisRandomReorderDenominator, $ThisReorderDelayDeltaMs, $UseTcp, $ThisDurationMs, $ThisPacing, $RateKbps, $Results);
        $RunResults.Runs.Add($RunResult)
        Write-Host $Row
        if ($RemoteResults -ne "") {
            $RemoteResult = Find-MatchingTest -TestResult $RunResult -RemoteResults $RemoteResults
            if ($null -ne $RemoteResult -and $RemoteResult.RateKbps -ne 0) {
                $MedianLastResult = $RemoteResult.RateKbps
                $PercentDiff = 100 * (($RateKbps - $MedianLastResult) / $MedianLastResult)
                $PercentDiffStr = $PercentDiff.ToString("#.##")
                if ($PercentDiff -ge 0) {
                    $PercentDiffStr = "+$PercentDiffStr"
                }
                Write-Output "Median: $RateKbps, Remote: $MedianLastResult, ($PercentDiffStr%)"
            } else {
                Write-Output "Median: $RateKbps"
            }
        } else {
            Write-Output "Median: $RateKbps"
        }
    }}}

}}}}}}

# Delete pktmon filter.
pktmon filter remove

$RunResults | ConvertTo-Json -Depth 100 | Out-File $OutputFile

# Kill any leftovers.
try { Stop-Process -Name secnetperf } catch { }
