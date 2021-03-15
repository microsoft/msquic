function Get-LatestCommitHash([string]$Branch) {
    $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/data/$Branch/commits.json"
    Write-Debug "Requesting: $Uri"
    try {
        $AllCommits = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Method 'GET' -ContentType "application/json"
        Write-Debug "Result: $AllCommits"
        $LatestResult = ($AllCommits | Sort-Object -Property Date -Descending)[0]
        Write-Debug "Latest Commit: $LatestResult"
    return $LatestResult.CommitHash
    } catch {
        return ""
    }
}

function Get-LatestWanTestResult([string]$Branch, [string]$CommitHash) {
    $Uri = "https://raw.githubusercontent.com/microsoft/msquic/performance/data/$Branch/$CommitHash/wan_data.json"
    Write-Debug "Requesting: $Uri"
    try {
        $LatestResult = Invoke-RestMethod -SkipHttpErrorCheck -Uri $Uri -Method 'GET' -ContentType "application/json"
        Write-Debug "Result: $LatestResult"
    return $LatestResult
    } catch {
        return ""
    }
}

$BranchName = "main"

$LastCommitHash = Get-LatestCommitHash -Branch $BranchName
$PreviousResults = Get-LatestWanTestResult -Branch $BranchName -CommitHash $LastCommitHash

$Key = 'Windows_x64_schael'

$PreviousResults.$Key.Length

class TestType {
    [int]$RttMS;

    [boolean] Equals([Object]$other) {
        return $this.Encryption -eq $other.Encryption -and
        $this.Loopback -eq $other.Loopback -and
        $this.NumberOfStreams -eq $other.NumberOfStreams -and
        $this.SendBuffering -eq $other.SendBuffering -and
        $this.ServerToClient -eq $other.ServerToClient
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

$RunResults = [Results]::new($PlatformName)

$RunResults | ConvertTo-Json -Depth 100
