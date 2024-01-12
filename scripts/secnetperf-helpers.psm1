<#
.SYNOPSIS
    Various helper functions for running secnetperf tests.
#>

# Write a GitHub error message to the console.
function Write-GHError($msg) {
    Write-Host "::error::$msg"
}

# Write a GitHub warning message to the console.
function Write-GHWarning($msg) {
    Write-Host "::warning::$msg"
}

# Waits for a remote job to be ready based on looking for a particular string in
# the output.
function Start-RemoteServer {
    param ($Session, $Command)
    # Start the server on the remote in an async job.
    $Job = Invoke-Command -Session $Session -ScriptBlock { iex $Using:Command } -AsJob
    # Poll the job for 10 seconds to see if it started.
    $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    while ($StopWatch.ElapsedMilliseconds -lt 10000) {
        $CurrentResults = Receive-Job -Job $Job -Keep -ErrorAction Continue
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            $DidMatch = $CurrentResults -match "Started!" # Look for the special string to indicate success.
            if ($DidMatch) {
                return $Job
            }
        }
        Start-Sleep -Seconds 0.1 | Out-Null
    }

    # On failure, dump the output of the job.
    Stop-Job -Job $Job
    $RemoteResult = Receive-Job -Job $Job -ErrorAction Stop
    $RemoteResult = $RemoteResult -join "`n"
    Write-GHWarning $RemoteResult.ToString()
    throw "Server failed to start!"
}

# Sends a special UDP packet to tell the remote secnetperf to shutdown, and then
# waits for the job to complete. Finally, it returns the console output of the
# job.
function Stop-RemoteServer {
    param ($Job, $RemoteAddress)
    # Ping side-channel socket on 9999 to tell the app to die
    $Socket = New-Object System.Net.Sockets.UDPClient
    $BytesToSend = @(
        0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
        0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c
    )
    for ($i = 0; $i -lt 30; $i++) {
        $Socket.Send($BytesToSend, $BytesToSend.Length, $RemoteAddress, 9999) | Out-Null
        $Completed = Wait-Job -Job $Job -Timeout 1
        if ($null -ne $Completed) {
            return
        }
    }

    # On failure, dump the output of the job.
    Stop-Job -Job $Job
    $RemoteResult = Receive-Job -Job $Job -ErrorAction Stop
    $RemoteResult = $RemoteResult -join "`n"
    Write-GHWarning $RemoteResult.ToString()
    throw "Server failed to stop!"
}

class TestResult {
    [string]$Metric;
    [System.Object[]]$Values;
    [bool]$EncounteredFailures;

    TestResult (
        [string]$Metric,
        [System.Object[]]$Values,
        [bool]$EncounteredFailures
    ) {
        $this.Metric = $Metric;
        $this.Values = $Values;
        $this.EncounteredFailures = $EncounteredFailures;
    }
}

# Invokes secnetperf with the given arguments for both TCP and QUIC.
function Invoke-Secnetperf {
    param ($Session, $RemoteName, $RemoteDir, $SecNetPerfPath, $LogProfile, $ExeArgs)

    $Results = @(@(), @())
    $encounterFailures = $true

    # TODO: This logic is pretty fragile. Needs improvement.
    $metric = "throughput-download"
    if ($exeArgs.Contains("plat:1")) {
        $metric = "latency"
    } elseif ($exeArgs.Contains("-up")) {
        $metric = "throughput-upload"
    }

    for ($tcp = 0; $tcp -lt 2; $tcp++) {

    $execMode = $ExeArgs.Substring(0, $ExeArgs.IndexOf(' ')) # First arg is the exec mode
    $command = "./$SecNetPerfPath -target:netperf-peer $ExeArgs -tcp:$tcp -trimout"
    Write-Host "> $command"

    if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
        .\scripts\log.ps1 -Start -Profile $LogProfile
    }

    try {

    # Start the server running
    $Job = Start-RemoteServer $Session "$RemoteDir/$SecNetPerfPath $execMode"

    for ($try = 0; $try -lt 3; $try++) {
        try {
            $rawOutput = Invoke-Expression $command
            if ($null -eq $rawOutput) {
                throw "Output is empty!."
            }
            if ($rawOutput.Contains("Error")) {
                throw $rawOutput.Substring(7) # Skip over the 'Error: ' prefix
            }
            Write-Host $rawOutput
            if ($exeArgs.Contains("plat:1")) {
                $latency_percentiles = '(?<=\d{1,3}(?:\.\d{1,2})?th: )\d+'
                $Results[$tcp] += [regex]::Matches($rawOutput, $latency_percentiles) | ForEach-Object {$_.Value}
            } else {
                $rawOutput -match '@ (\d+) kbps'
                $Results[$tcp] += $matches[1]
            }
        } catch {
            Write-GHError $_
            $encounterFailures = $true
        }
        Start-Sleep -Seconds 1
    }

    } catch {
        Write-GHError "Exception while running test case!"
        Write-GHError $_
        $_ | Format-List *
        $encounterFailures = $true
    } finally {
        # Stop the server
        try { Stop-RemoteServer $Job $RemoteName } catch { } # Ignore failures for now
        if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
            .\scripts\log.ps1 -Stop -OutputPath "./artifacts/logs/$metric-$tcp/client" -RawLogOnly
        }
    }}

    return [TestResult]::New($metric, $Results, $encounterFailures)
}
