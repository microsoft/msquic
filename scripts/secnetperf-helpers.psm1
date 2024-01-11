<#
.SYNOPSIS
    Various helper functions for running secnetperf tests.
#>

# Write a GitHub error message to the console.
function Write-GHError($msg) {
    Write-Host "::error::$msg"
}

# Waits for a remote job to be ready based on looking for a particular string in
# the output.
function Start-RemoteServer {
    param ($Command)
    $Job = Invoke-Command -Session $Session -ScriptBlock { $Using:Command } -AsJob
    $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    $Started = $false
    while ($StopWatch.ElapsedMilliseconds -lt 10000) {
        $CurrentResults = Receive-Job -Job $Job -Keep -ErrorAction Continue
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            $DidMatch = $CurrentResults -match "Started!"
            if ($DidMatch) {
                $Started = $true
                break;
            }
        }
        Start-Sleep -Seconds 0.1 | Out-Null
    }
    if (!$Started) {
        Stop-Job -Job $Job
        $RemoteResult = Receive-Job -Job $Job -ErrorAction Stop
        $RemoteResult = $RemoteResult -join "`n"
        Write-GHError "Server failed to start! Output:"
        Write-Output $RemoteResult
        return $null
    }
    return $Job
}

# Sends a special UDP packet to tell the remote secnetperf to shutdown, and then
# waits for the job to complete. Finally, it returns the console output of the
# job.
function Stop-RemoteServer {
    param ($Job, $ErrorAction = "Stop")
    # Ping side-channel socket on 9999 to tell the app to die
    $Socket = New-Object System.Net.Sockets.UDPClient
    $BytesToSend = @(
        0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
        0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c
    )
    for ($i = 0; $i -lt 120; $i++) {
        $Socket.Send($BytesToSend, $BytesToSend.Length, $RemoteAddress, 9999) | Out-Null
        $Completed = Wait-Job -Job $Job -Timeout 1
        if ($null -ne $Completed) {
            break;
        }
    }

    Stop-Job -Job $Job | Out-Null
    $RetVal = Receive-Job -Job $Job -ErrorAction $ErrorAction
    $RetVal = $RetVal -join "`n"
}

# Invokes all the secnetperf tests.
function Invoke-SecnetperfTest($testIds, $commands, $exe, $json, $LogProfile) {

    Write-Host "Running Secnetperf tests..."

    $SQL = @"
"@
    $json = @{}

    for ($i = 0; $i -lt $commands.Count; $i++) {
    for ($tcp = 0; $tcp -lt 2; $tcp++) {

    if ($LogProfile -ne "" -and $LogProfile -ne "NULL") { # Start logging.
        Write-Host "Starting logging with log profile: $LogProfile..."
        .\scripts\log.ps1 -Start -Profile $LogProfile
    }

    for ($try = 0; $try -lt 3; $try++) {
        $command = "$exe -target:netperf-peer $($commands[$i]) -tcp:$tcp -trimout"
        Write-Host "Running test: $command"
        try {
            $rawOutput = Invoke-Expression $command
        } catch {
            Write-GHError "Failed to run test: $($commands[$i])"
            Write-GHError $_
            $script:encounterFailures = $true
            continue
        }

        if ($null -eq $rawOutput) {
            Write-GHError "RawOutput is null. Failed to run test: $($commands[$i])"
            $script:encounterFailures = $true
            continue
        }

        if ($rawOutput.Contains("Error")) {
            $rawOutput = $rawOutput.Substring(7) # Skip over the 'Error: ' prefix
            Write-GHError $rawOutput
            $script:encounterFailures = $true
            continue
        }

        Write-Host $rawOutput

        if ($testIds[$i].Contains("rps")) {
            $latency_percentiles = '(?<=\d{1,3}(?:\.\d{1,2})?th: )\d+'
            $Perc = [regex]::Matches($rawOutput, $latency_percentiles) | ForEach-Object {$_.Value}
            $json[$testIds[$i]] = $Perc
            # TODO: SQL += ...
            continue
        }

        $throughput = '@ (\d+) kbps'

        $testId = $testIds[$i]
        if ($tcp -eq 1) {
            $testId += "-tcp"
        } else {
            $testId += "quic"
        }
        $testId += "-$MsQuicCommit"

        foreach ($line in $rawOutput) {
            if ($line -match $throughput) {

                $num = $matches[1]

                # Generate SQL statement
                $SQL += @"

INSERT INTO Secnetperf_test_runs (Secnetperf_test_ID, Client_environment_ID, Server_environment_ID, Result, Latency_stats_ID, Units)
VALUES ('$($testIds[$i])', 'azure_vm', 'azure_vm', $num, NULL, 'kbps');

"@

                # Generate JSON
                $json[$testIds[$i]] = $num
                break
            }
        }

        if ($LogProfile -ne "" -and $LogProfile -ne "NULL") { # Stop logging.
            Write-Host "Stopping logging..."
            .\scripts\log.ps1 -Stop -OutputPath ".\artifacts\logs\$command"
        }

        Start-Sleep -Seconds 1
    }



    }}

    return $SQL
}
