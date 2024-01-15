<#
.SYNOPSIS
    Various helper functions for running secnetperf tests.
#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Path to the WER registry key used for collecting dumps on Windows.
$WerDumpRegPath = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\secnetperf.exe"

# Write a GitHub error message to the console.
function Write-GHError($msg) {
    Write-Host "::error::$msg"
}

# Configured the remote machine to collect dumps on crash.
function Configure-DumpCollection {
    param ($Session)
    if ($isWindows) {
        Invoke-Command -Session $Session -ScriptBlock {
            $DumpDir = "C:/_work/quic/artifacts/crashdumps"
            New-Item -Path $DumpDir -ItemType Directory -ErrorAction Ignore | Out-Null
            New-Item -Path $Using:WerDumpRegPath -Force -ErrorAction Ignore | Out-Null
            Set-ItemProperty -Path $Using:WerDumpRegPath -Name DumpFolder -Value $DumpDir | Out-Null
            Set-ItemProperty -Path $Using:WerDumpRegPath -Name DumpType -Value 2 | Out-Null
        }
        $DumpDir = Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts/crashdumps"
        New-Item -Path $DumpDir -ItemType Directory -ErrorAction Ignore | Out-Null
        New-Item -Path $WerDumpRegPath -Force -ErrorAction Ignore | Out-Null
        Set-ItemProperty -Path $WerDumpRegPath -Name DumpFolder -Value $DumpDir | Out-Null
        Set-ItemProperty -Path $WerDumpRegPath -Name DumpType -Value 2 | Out-Null
    } else {
        # TODO: Configure Linux to collect dumps.
    }
}

# Collects any crash dumps that were generated locally by secnetperf.
function Collect-LocalDumps {
    param ($OutputDir)
    if ($isWindows) {
        $DumpFiles = (Get-ChildItem "./artifacts/crashdumps") | Where-Object { $_.Extension -eq ".dmp" }
        if ($DumpFiles) {
            mkdir $OutputDir | Out-Null
            foreach ($File in $DumpFiles) {
                Copy-Item -Path $File.FullName -Destination $OutputDir
            }
            # Delete all the files in the crashdumps folder.
            Remove-Item -Path "./artifacts/crashdumps/*" -Force
            return $true
        }
    } else {
    }
    return $false
}

# Collect any crash dumps that were generated on the remote machine.
function Collect-RemoteDumps {
    param ($Session, $OutputDir)
    if ($isWindows) {
        $DumpFiles = Invoke-Command -Session $Session -ScriptBlock {
            Get-ChildItem "C:/_work/quic/artifacts/crashdumps" | Where-Object { $_.Extension -eq ".dmp" }
        }
        if ($DumpFiles) {
            mkdir $OutputDir | Out-Null
            foreach ($File in $DumpFiles) {
                Copy-Item -FromSession $Session -Path $File.FullName -Destination $OutputDir
            }
            # Delete all the files in the crashdumps folder.
            Invoke-Command -Session $Session -ScriptBlock {
                Remove-Item -Path "C:/_work/quic/artifacts/crashdumps/*" -Force
            }
            return $true
        }
    } else {
    }
    return $false
}

# Waits for a remote job to be ready based on looking for a particular string in
# the output.
function Start-RemoteServer {
    param ($Session, $Command)
    # Start the server on the remote in an async job.
    $Job = Invoke-Command -Session $Session -ScriptBlock { iex $Using:Command } -AsJob
    # Poll the job for 10 seconds to see if it started.
    $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    while ($StopWatch.ElapsedMilliseconds -lt 30000) {
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
    Write-Host $RemoteResult.ToString()
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
    Write-Host $RemoteResult.ToString()
    throw "Server failed to stop!"
}

class TestResult {
    [String]$Metric;
    [System.Object[]]$Values;
    [Boolean]$HasFailures;

    TestResult (
        [String]$Metric,
        [System.Object[]]$Values,
        [Boolean]$HasFailures
    ) {
        $this.Metric = $Metric;
        $this.Values = $Values;
        $this.HasFailures = $HasFailures;
    }
}

# Invokes secnetperf with the given arguments for both TCP and QUIC.
function Invoke-Secnetperf {
    param ($Session, $RemoteName, $RemoteDir, $SecNetPerfPath, $LogProfile, $ExeArgs)

    $values = @(@(), @())
    $hasFailures = $false

    # TODO: This logic is pretty fragile. Needs improvement.
    $metric = "throughput-download"
    if ($exeArgs.Contains("plat:1")) {
        $metric = "latency"
    } elseif ($exeArgs.Contains("prate:1")) {
        $metric = "hps"
    } elseif ($exeArgs.Contains("-up")) {
        $metric = "throughput-upload"
    }

    for ($tcp = 0; $tcp -lt 2; $tcp++) {

    $execMode = $ExeArgs.Substring(0, $ExeArgs.IndexOf(' ')) # First arg is the exec mode
    $command = "./$SecNetPerfPath -target:netperf-peer $ExeArgs -tcp:$tcp -trimout -watchdog:45000"
    Write-Host "> $command"

    if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
        Invoke-Command -Session $Session -ScriptBlock {
            try { & "$Using:RemoteDir/scripts/log.ps1" -Cancel } catch {} # Cancel any previous logging
            & "$Using:RemoteDir/scripts/log.ps1" -Start -Profile $Using:LogProfile -ProfileInScriptDirectory
        }
        try { .\scripts\log.ps1 -Cancel } catch {} # Cancel any previous logging
        .\scripts\log.ps1 -Start -Profile $LogProfile
    }

    try {

    # Start the server running.
    $Job = Start-RemoteServer $Session "$RemoteDir/$SecNetPerfPath $execMode"

    # Run the test multiple times, failing (for now) only if all tries fail.
    $successCount = 0
    for ($try = 0; $try -lt 3; $try++) {
        try {
            $rawOutput = Invoke-Expression $command
            if ($null -eq $rawOutput) {
                throw "secnetperf: No console output (possibly crashed)!"
            }
            if ($rawOutput.Contains("Error")) {
                throw "secnetperf: $($rawOutput.Substring(7))" # Skip over the 'Error: ' prefix
            }
            Write-Host $rawOutput
            if ($metric -eq "latency") {
                $latency_percentiles = '(?<=\d{1,3}(?:\.\d{1,2})?th: )\d+'
                $values[$tcp] += [regex]::Matches($rawOutput, $latency_percentiles) | ForEach-Object {$_.Value}
            } elseif ($metric -eq "hps") {
                $rawOutput -match '(\d+) HPS'
                $values[$tcp] += $matches[1]
            } else { # throughput
                $rawOutput -match '@ (\d+) kbps'
                $values[$tcp] += $matches[1]
            }
            $successCount++
        } catch {
            Write-GHError $_
            #$hasFailures = $true
        }
        Start-Sleep -Seconds 1 | Out-Null
    }
    if ($successCount -eq 0) {
        $hasFailures = $true # For now, consider failure only if all failed
        Write-GHError "secnetperf: All test tries failed!"
    }

    } catch {
        Write-GHError "Exception while running test case!"
        Write-GHError $_
        $_ | Format-List *
        $hasFailures = $true
    } finally {
        $ArtifactName = $tcp -eq 0 ? "$metric-quic" : "$metric-tcp"

        # Stop the server.
        try { Stop-RemoteServer $Job $RemoteName | Out-Null } catch { } # Ignore failures for now

        # Stop logging and copy the logs to the artifacts folder.
        if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
            try { .\scripts\log.ps1 -Stop -OutputPath "./artifacts/logs/$ArtifactName/client" -RawLogOnly }
            catch { Write-Host "Failed to stop logging on client!" }
            Invoke-Command -Session $Session -ScriptBlock {
                try {
                    & "$Using:RemoteDir/scripts/log.ps1" -Stop -OutputPath "$Using:RemoteDir/artifacts/logs/$Using:ArtifactName/server" -RawLogOnly
                    dir "$Using:RemoteDir/artifacts/logs/$Using:ArtifactName"
                } catch { Write-Host "Failed to stop logging on server!" }
            }
            try { Copy-Item -FromSession $Session "$RemoteDir/artifacts/logs/$ArtifactName/*" "./artifacts/logs/$ArtifactName/" }
            catch { Write-Host "Failed to copy server logs!" }
        }

        # Grab any crash dumps that were generated.
        if (Collect-LocalDumps "./artifacts/logs/$ArtifactName/clientdumps") {
            Write-Host "Dump file(s) generated locally"
            $hasFailures = $true
        }
        if (Collect-RemoteDumps $Session "./artifacts/logs/$ArtifactName/serverdumps") {
            Write-Host "Dump file(s) generated on peer"
            $hasFailures = $true
        }
    }}

    return [TestResult]::new($metric, $values, $hasFailures)
}
