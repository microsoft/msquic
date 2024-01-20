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

# Returns the full path to a file in the repo, given a relative path.
function Repo-Path {
    param ($Path)
    return Join-Path (Split-Path $PSScriptRoot -Parent) $Path
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
        $DumpDir = Repo-Path "artifacts/crashdumps"
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
            mkdir $OutputDir -ErrorAction Ignore | Out-Null
            foreach ($File in $DumpFiles) {
                Copy-Item -Path $File.FullName -Destination $OutputDir
            }
            # Delete all the files in the crashdumps folder.
            Remove-Item -Path "./artifacts/crashdumps/*" -Force
            return $true
        }
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
            mkdir $OutputDir -ErrorAction Ignore | Out-Null
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
        # TODO - Collect Linux dumps.
    }
    return $false
}

# Waits for a given driver to be started up to a given timeout.
function Wait-DriverStarted {
    param ($DriverName, $TimeoutMs)
    $stopWatch = [system.diagnostics.stopwatch]::StartNew()
    while ($stopWatch.ElapsedMilliseconds -lt $TimeoutMs) {
        $Driver = Get-Service -Name $DriverName -ErrorAction Ignore
        if ($null -ne $Driver -and $Driver.Status -eq "Running") {
            Write-Host "$DriverName is running"
            return
        }
        Start-Sleep -Seconds 0.1 | Out-Null
    }
    throw "$DriverName failed to start!"
}

# Download and install XDP on both local and remote machines.
function Install-XDP {
    param ($Session, $RemoteDir)
    $installerUri = (Get-Content (Join-Path $PSScriptRoot "xdp.json") | ConvertFrom-Json).installer
    $msiPath = Repo-Path "artifacts/xdp.msi"
    Write-Host "Downloading XDP installer"
    Invoke-WebRequest -Uri $installerUri -OutFile $msiPath
    Write-Host "Installing XDP driver locally"
    msiexec.exe /i $msiPath /quiet | Out-Null
    Wait-DriverStarted "xdp" 10000
    Write-Host "Installing XDP driver on peer"
    $remoteMsiPath = Join-Path $RemoteDir "artifacts/xdp.msi"
    Copy-Item -ToSession $Session $msiPath -Destination $remoteMsiPath
    $WaitDriverStartedStr = "${function:Wait-DriverStarted}"
    Invoke-Command -Session $Session -ScriptBlock {
        msiexec.exe /i $Using:remoteMsiPath /quiet | Out-Host
        $WaitDriverStarted = [scriptblock]::Create($Using:WaitDriverStartedStr)
        & $WaitDriverStarted xdp 10000
    }
}

# Uninstalls the XDP driver on both local and remote machines.
function Uninstall-XDP {
    param ($Session, $RemoteDir)
    $msiPath = Repo-Path "artifacts/xdp.msi"
    $remoteMsiPath = Join-Path $RemoteDir "artifacts/xdp.msi"
    Write-Host "Uninstalling XDP driver locally"
    try { msiexec.exe /x $msiPath /quiet | Out-Null } catch {}
    Write-Host "Uninstalling XDP driver on peer"
    Invoke-Command -Session $Session -ScriptBlock {
        try { msiexec.exe /x $Using:remoteMsiPath /quiet | Out-Null } catch {}
    }
}

# Installs the necessary drivers to run WSK tests.
function Install-Kernel {
    param ($Session, $RemoteDir, $SecNetPerfDir)
    $localSysPath = Repo-Path "$SecNetPerfDir/msquicpriv.sys"
    $remoteSysPath = Join-Path $RemoteDir "$SecNetPerfDir/msquicpriv.sys"
    Write-Host "Installing msquicpriv locally"
    if (!(Test-Path $localSysPath)) { throw "msquicpriv.sys not found!" }
    sc.exe create "msquicpriv" type= kernel binpath= $localSysPath start= demand | Out-Null
    net.exe start msquicpriv
    Write-Host "Installing msquicpriv on peer"
    Invoke-Command -Session $Session -ScriptBlock {
        if (!(Test-Path $Using:remoteSysPath)) { throw "msquicpriv.sys not found!" }
        sc.exe create "msquicpriv" type= kernel binpath= $Using:remoteSysPath start= demand | Out-Null
        net.exe start msquicpriv
    }
}

# Stops and uninstalls the WSK driver on both local and remote machines.
function Uninstall-Kernel {
    param ($Session)
    Write-Host "Stopping kernel drivers locally"
    try { net.exe stop secnetperfdrvpriv /y 2>&1 | Out-Null } catch {}
    try { net.exe stop msquicpriv /y 2>&1 | Out-Null } catch {}
    Write-Host "Stopping kernel drivers on peer"
    Invoke-Command -Session $Session -ScriptBlock {
        try { net.exe stop secnetperfdrvpriv 2>&1 /y | Out-Null } catch {}
        try { net.exe stop msquicpriv 2>&1 /y | Out-Null } catch {}
    }
    Write-Host "Uninstalling drivers locally"
    try { sc.exe delete secnetperfdrvpriv /y 2>&1 | Out-Null } catch {}
    try { sc.exe delete msquicpriv /y 2>&1 | Out-Null } catch {}
    Write-Host "Uninstalling drivers on peer"
    Invoke-Command -Session $Session -ScriptBlock {
        try { sc.exe delete secnetperfdrvpriv /y 2>&1 | Out-Null } catch {}
        try { sc.exe delete msquicpriv /y 2>&1 | Out-Null } catch {}
    }
}

# Cleans up all state after a run.
function Cleanup-State {
    param ($Session, $RemoteDir)
    Write-Host "Cleaning up any previous state"
    Get-Process | Where-Object { $_.Name -eq "secnetperf" } | Stop-Process
    Invoke-Command -Session $Session -ScriptBlock {
        Get-Process | Where-Object { $_.Name -eq "secnetperf" } | Stop-Process
    }
    Uninstall-Kernel $Session | Out-Null
    Uninstall-XDP $Session $RemoteDir | Out-Null
    if ($null -ne (Get-Process | Where-Object { $_.Name -eq "secnetperf" })) { throw "secnetperf still running!" }
    if ($null -ne (Get-Service xdp -ErrorAction Ignore)) { throw "xdp still running!" }
    if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "secnetperfdrvpriv still running!" }
    if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "msquicpriv still running!" }
    Invoke-Command -Session $Session -ScriptBlock {
        if ($null -ne (Get-Process | Where-Object { $_.Name -eq "secnetperf" })) { throw "secnetperf still running remotely!" }
        if ($null -ne (Get-Service xdp -ErrorAction Ignore)) { throw "xdp still running remotely!" }
        if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "secnetperfdrvpriv still running remotely!" }
        if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "msquicpriv still running remotely!" }
    }
}

# Waits for a remote job to be ready based on looking for a particular string in
# the output.
function Start-RemoteServer {
    param ($Session, $Command)
    # Start the server on the remote in an async job.
    $job = Invoke-Command -Session $Session -ScriptBlock { iex $Using:Command } -AsJob
    # Poll the job for 10 seconds to see if it started.
    $stopWatch = [system.diagnostics.stopwatch]::StartNew()
    while ($stopWatch.ElapsedMilliseconds -lt 30000) {
        $CurrentResults = Receive-Job -Job $job -Keep -ErrorAction Continue
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            $DidMatch = $CurrentResults -match "Started!" # Look for the special string to indicate success.
            if ($DidMatch) {
                return $job
            }
        }
        Start-Sleep -Seconds 0.1 | Out-Null
    }

    # On failure, dump the output of the job.
    Stop-Job -Job $job
    $RemoteResult = Receive-Job -Job $job -ErrorAction Stop
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

# Creates a new local process to asynchronously run the test.
function Start-LocalTest {
    param ($FullPath, $FullArgs, $OutputDir)
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    if ($IsWindows) {
        $pinfo.FileName = $FullPath
        $pinfo.Arguments = $FullArgs
    } else {
        $pinfo.FileName = "bash"
        $pinfo.Arguments = "-c `"ulimit -c unlimited && LSAN_OPTIONS=report_objects=1 ASAN_OPTIONS=disable_coredump=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $FullPath $FullArgs && echo ''`""
        $pinfo.WorkingDirectory = $OutputDir
    }
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p
}

# Use procdump64.exe to collect a dump of a local process.
function Collect-LocalDump {
    param ($Process, $OutputDir)
    if (!$isWindows) { return } # Not supported on Windows
    $dumpExe = Repo-Path "artifacts/corenet-ci-main/vm-setup/procdump64.exe"
    if (!(Test-Path $dumpExe)) {
        Write-Host "procdump64.exe not found!"
        return;
    }
    $dumpPath = Join-Path $OutputDir "secnetperf.$($Process.Id).dmp"
    $dumpArgs = "-accepteula -ma $($Process.Id) $dumpPath"
    & $dumpExe $dumpArgs
}

# Waits for a local test process to complete, and then returns the console output.
function Wait-LocalTest {
    param ($Process, $OutputDir, $TimeoutMs)
    $StdOut = $Process.StandardOutput.ReadToEndAsync()
    $StdError = $Process.StandardError.ReadToEndAsync()
    if (!$Process.WaitForExit($TimeoutMs)) {
        Collect-LocalDump $Process $OutputDir
        try { $Process.Kill() } catch { }
        try {
            [System.Threading.Tasks.Task]::WaitAll(@($StdOut, $StdError))
            Write-Host $StdOut.Result.Trim()
        } catch {}
        throw "secnetperf: Client timed out!"
    }
    if ($Process.ExitCode -ne 0) {
        try {
            [System.Threading.Tasks.Task]::WaitAll(@($StdOut, $StdError))
            Write-Host $StdOut.Result.Trim()
        } catch {}
        throw "secnetperf: Nonzero exit code: $($Process.ExitCode)"
    }
    [System.Threading.Tasks.Task]::WaitAll(@($StdOut, $StdError))
    $consoleTxt = $StdOut.Result.Trim()
    if ($null -eq $consoleTxt -or $consoleTxt.Length -eq 0) {
        throw "secnetperf: No console output (possibly crashed)!"
    }
    if ($consoleTxt.Contains("Error")) {
        throw "secnetperf: $($consoleTxt.Substring(7))" # Skip over the 'Error: ' prefix
    }
    return $consoleTxt
}

# Parses the console output of secnetperf to extract the metric value.
function Get-TestOutput {
    param ($Output, $Metric)
    if ($Metric -eq "latency") {
        $latency_percentiles = '(?<=\d{1,3}(?:\.\d{1,2})?th: )\d+'
        return [regex]::Matches($Output, $latency_percentiles) | ForEach-Object {$_.Value}
    } elseif ($Metric -eq "hps") {
        $rawOutput -match '(\d+) HPS' | Out-Null
        return $matches[1]
    } else { # throughput
        $Output -match '@ (\d+) kbps' | Out-Null
        return $matches[1]
    }
}

# Invokes secnetperf with the given arguments for both TCP and QUIC.
function Invoke-Secnetperf {
    param ($Session, $RemoteName, $RemoteDir, $SecNetPerfPath, $LogProfile, $ExeArgs, $io)
    # TODO: This logic is pretty fragile. Needs improvement.
    $metric = "throughput-download"
    if ($exeArgs.Contains("plat:1")) {
        $metric = "latency"
    } elseif ($exeArgs.Contains("prate:1")) {
        $metric = "hps"
    } elseif ($exeArgs.Contains("-up")) {
        $metric = "throughput-upload"
    }

    $values = @(@(), @())
    $hasFailures = $false
    $tcpSupported = ($io -ne "xdp" -and $io -ne "wsk") ? 1 : 0
    for ($tcp = 0; $tcp -le $tcpSupported; $tcp++) {

    # Set up all the parameters and paths for running the test.
    $execMode = $ExeArgs.Substring(0, $ExeArgs.IndexOf(' ')) # First arg is the exec mode
    $clientPath = Repo-Path $SecNetPerfPath
    $serverArgs = "$execMode -io:$io"
    $clientArgs = "-target:netperf-peer $ExeArgs -tcp:$tcp -trimout -watchdog:45000"
    if ($io -eq "xdp") {
        $serverArgs += " -pollidle:10000"
        $clientArgs += " -pollidle:10000"
    }
    if ($io -eq "wsk") {
        $serverArgs += " -driverNamePriv:secnetperfdrvpriv"
        $clientArgs += " -driverNamePriv:secnetperfdrvpriv"
    }
    $artifactName = $tcp -eq 0 ? "$metric-quic" : "$metric-tcp"
    New-Item -ItemType Directory "artifacts/logs/$artifactName" -ErrorAction Ignore | Out-Null
    $localDumpDir = Repo-Path "artifacts/logs/$artifactName/clientdumps"
    New-Item -ItemType Directory $localDumpDir -ErrorAction Ignore | Out-Null

    # Start logging on both sides, if configured.
    if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
        Invoke-Command -Session $Session -ScriptBlock {
            try { & "$Using:RemoteDir/scripts/log.ps1" -Cancel } catch {} # Cancel any previous logging
            & "$Using:RemoteDir/scripts/log.ps1" -Start -Profile $Using:LogProfile -ProfileInScriptDirectory
        }
        try { .\scripts\log.ps1 -Cancel } catch {} # Cancel any previous logging
        .\scripts\log.ps1 -Start -Profile $LogProfile
    }

    Write-Host "> secnetperf $serverArgs"
    Write-Host "> secnetperf $clientArgs"

    try {

    # Start the server running.
    $job = Start-RemoteServer $Session "$RemoteDir/$SecNetPerfPath $serverArgs"

    # Run the test multiple times, failing (for now) only if all tries fail.
    # TODO: Once all failures have been fixed, consider all errors fatal.
    $successCount = 0
    for ($try = 0; $try -lt 1; $try++) {
        try {
            $process = Start-LocalTest $clientPath $clientArgs $localDumpDir
            $rawOutput = Wait-LocalTest $process $localDumpDir 30000 # 1 minute timeout
            Write-Host $rawOutput
            $values[$tcp] += Get-TestOutput $rawOutput $metric
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
        # Stop the server.
        try { Stop-RemoteServer $job $RemoteName | Out-Null } catch { } # Ignore failures for now

        # Stop any logging and copy the logs to the artifacts folder.
        if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
            try { .\scripts\log.ps1 -Stop -OutputPath "./artifacts/logs/$artifactName/client" -RawLogOnly }
            catch { Write-Host "Failed to stop logging on client!" }
            Invoke-Command -Session $Session -ScriptBlock {
                try { & "$Using:RemoteDir/scripts/log.ps1" -Stop -OutputPath "$Using:RemoteDir/artifacts/logs/$Using:artifactName/server" -RawLogOnly }
                catch { Write-Host "Failed to stop logging on server!" }
            }
            try { Copy-Item -FromSession $Session "$RemoteDir/artifacts/logs/$artifactName/*" "./artifacts/logs/$artifactName/" -Recurse }
            catch { Write-Host "Failed to copy server logs!" }
        }

        # Grab any crash dumps that were generated.
        if (Collect-LocalDumps $localDumpDir) {
            Write-Host "Dump file(s) generated locally"
            #$hasFailures = $true
        }
        if (Collect-RemoteDumps $Session "./artifacts/logs/$artifactName/serverdumps") {
            Write-Host "Dump file(s) generated on peer"
            #$hasFailures = $true
        }
    }}

    return [pscustomobject]@{
        Metric = $metric
        Values = $values
        HasFailures = $hasFailures
    }
}
