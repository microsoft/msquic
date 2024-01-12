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

# Invokes secnetperf with the given arguments for both TCP and QUIC.
function Invoke-Secnetperf {
    param ($Session, $RemoteName, $RemoteDir, $SecNetPerfPath, $LogProfile, $ExeArgs, $MsQuicCommit, $testid, $SQL, $json)

    $encounterFailures = $true
    $env = $isWindows ? 1 : 2

    # TODO: Improve this stuff
    $metric = "throughput-download"
    if ($exeArgs.Contains("plat:1")) {
        $metric = "latency"
    } elseif ($exeArgs.Contains("-up")) {
        $metric = "throughput-upload"
    }

    for ($tcp = 0; $tcp -lt 2; $tcp++) {

    $execMode = $ExeArgs.Substring(0, $ExeArgs.IndexOf(' ')) # First arg is the exec mode
    $transport = $tcp -eq 1 ? "tcp" : "quic"
    $SQL += @"

INSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Kernel_mode, Run_arguments) VALUES ($testid, 0, "$ExeArgs -tcp:$tcp")

"@

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
        } catch {
            Write-GHError "Invoke-Expression exception encountered!"
            Write-GHError $_
            $_ | Format-List *
            $encounterFailures = $true
            continue
        }

        if ($null -eq $rawOutput) {
            Write-GHError "RawOutput is null."
            $encounterFailures = $true
            continue
        }

        if ($rawOutput.Contains("Error")) {
            $rawOutput = $rawOutput.Substring(7) # Skip over the 'Error: ' prefix
            Write-GHError $rawOutput
            $encounterFailures = $true
            continue
        }

        Write-Host $rawOutput

        if ($exeArgs.Contains("plat:1")) {
            $latency_percentiles = '(?<=\d{1,3}(?:\.\d{1,2})?th: )\d+'
            $Perc = [regex]::Matches($rawOutput, $latency_percentiles) | ForEach-Object {$_.Value}
            Write-Host "json['$metric-$transport'] = $Perc"
            $json["$metric-$transport"] = $Perc
            # TODO: SQL += ...
            continue
        }

        $rawOutput -match '@ (\d+) kbps'
        $num = $matches[1]
        # Generate SQL statement. Assume LAST_INSERT_ROW_ID()
        $SQL += @"

INSERT INTO Secnetperf_test_runs (Secnetperf_test_ID, Secnetperf_commit, Client_environment_ID, Server_environment_ID, Result, Latency_stats_ID)
VALUES ($testid, '$MsQuicCommit', $env, $env, $num, NULL);

"@
        # Generate JSON as intermediary file for dashboard
        Write-Host "json['$metric-$transport'] = $num"
        $json["$metric-$transport"] = $num

        Start-Sleep -Seconds 1
    }

    } catch {
        Write-GHError "Inner exception while running test case!"
        Write-GHError $_
        $_ | Format-List *
        $encounterFailures = $true
    } finally {
        # Stop the server
        Stop-RemoteServer $Job $RemoteName
        if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
            .\scripts\log.ps1 -Stop -OutputPath "./artifacts/logs/$metric-$transport/client" -RawLogOnly
        }
    }

    } # end for tcp

    return $SQL, $json, $encounterFailures
}
