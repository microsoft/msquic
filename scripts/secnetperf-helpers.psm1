<#
.SYNOPSIS
    Various helper functions for running secnetperf tests.
#>

Set-StrictMode -Version "Latest"
$PSDefaultParameterValues["*:ErrorAction"] = "Stop"


$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 7) {
    $isWindows = $true
}


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
                $NewFileName = $File.Name -replace "secnetperf.exe", "secnetperf.exe.client"
                $NewFilePath = Join-Path $OutputDir $NewFileName
                Copy-Item -Path $File.FullName -Destination $NewFilePath
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
                $NewFileName = $File.Name -replace "secnetperf.exe", "secnetperf.exe.server"
                $NewFilePath = Join-Path $OutputDir $NewFileName
                Copy-Item -FromSession $Session -Path $File.FullName -Destination $NewFilePath
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

# Use procdump64.exe to collect a dump of a local process.
function Collect-LocalDump {
    param ($Process, $OutputDir)
    if (!$isWindows) { return } # Not supported on Windows
    $procDump = Repo-Path "artifacts/corenet-ci-main/vm-setup/procdump64.exe"
    if (!(Test-Path $procDump)) {
        Write-Host "procdump64.exe not found!"
        return;
    }
    $dumpPath = Join-Path $OutputDir "secnetperf.exe.client.$($Process.Id).dmp"
    & $procDump -accepteula -ma $($Process.Id) $dumpPath
}

# Use livekd64.exe to collect a dump of the kernel.
function Collect-LiveKD {
    param ($OutputDir, $Prefix)
    if (!$isWindows) { return } # Not supported on Windows
    $liveKD = Repo-Path "artifacts/corenet-ci-main/vm-setup/livekd64.exe"
    $KD = Repo-Path "artifacts/corenet-ci-main/vm-setup/kd.exe"
    $dumpPath = Join-Path $OutputDir "kernel.$Prefix.$(New-Guid).dmp"
    & $liveKD -o $dumpPath -k $KD -ml -accepteula
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
    whoami
    Invoke-WebRequest -Uri $installerUri -OutFile $msiPath -UseBasicParsing
    Write-Host "Installing XDP driver locally"
    msiexec.exe /i $msiPath /quiet | Out-Null
    $Size = Get-FileHash $msiPath
    Write-Host "MSI file hash: $Size"
    Wait-DriverStarted "xdp" 10000
    Write-Host "Installing XDP driver on peer"

    if ($Session -eq "NOT_SUPPORTED") {
        NetperfSendCommand "Install_XDP;$installerUri"
        NetperfWaitServerFinishExecution
        return
    }

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

    if ($Session -eq "NOT_SUPPORTED") {
        NetperfSendCommand "Install_Kernel"
        NetperfWaitServerFinishExecution
        return
    }

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
    if ($null -ne (Get-Process | Where-Object { $_.Name -eq "secnetperf" })) { throw "secnetperf still running!" }
    Invoke-Command -Session $Session -ScriptBlock {
        if ($null -ne (Get-Process | Where-Object { $_.Name -eq "secnetperf" })) { throw "secnetperf still running remotely!" }
    }
    if ($isWindows) {
        Uninstall-Kernel $Session | Out-Null
        Uninstall-XDP $Session $RemoteDir | Out-Null
        if ($null -ne (Get-Service xdp -ErrorAction Ignore)) { throw "xdp still running!" }
        if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "secnetperfdrvpriv still running!" }
        if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "msquicpriv still running!" }
        Invoke-Command -Session $Session -ScriptBlock {
            if ($null -ne (Get-Process | Where-Object { $_.Name -eq "secnetperf" })) { throw "secnetperf still running remotely!" }
            if ($null -ne (Get-Service xdp -ErrorAction Ignore)) { throw "xdp still running remotely!" }
            if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "secnetperfdrvpriv still running remotely!" }
            if ($null -ne (Get-Service msquicpriv -ErrorAction Ignore)) { throw "msquicpriv still running remotely!" }
        }
        # Clean up any ETL residue.
        try { .\scripts\log.ps1 -Cancel }
        catch { Write-Host "Failed to stop logging on client!" }
        Invoke-Command -Session $Session -ScriptBlock {
            try { & "$Using:RemoteDir/scripts/log.ps1" -Cancel }
            catch { Write-Host "Failed to stop logging on server!" }
        }
    } else {
        # iterate all interface and "ip link set ${iface} xdp off"
        if ((ip link show) -match "xdp") {
            $ifaces = ip link show | grep -oP '^\d+: \K[\w@]+' | cut -d'@' -f1
            foreach ($xdp in @('xdp', 'xdpgeneric')) {
                foreach ($iface in $ifaces) {
                    sudo ip link set $iface $xdp off
                }
            }
        }
        Invoke-Command -Session $Session -ScriptBlock {
            if ((ip link show) -match "xdp") {
                $ifaces = ip link show | grep -oP '^\d+: \K[\w@]+' | cut -d'@' -f1
                foreach ($xdp in @('xdp', 'xdpgeneric')) {
                    foreach ($iface in $ifaces) {
                        sudo ip link set $iface $xdp off
                    }
                }
            }
        }
    }
}

# Waits for a remote job to be ready based on looking for a particular string in
# the output.
function Start-RemoteServer {
    param ($Session, $Command, $ServerArgs, $UseSudo)
    # Start the server on the remote in an async job.

    if ($UseSudo) {
        $job = Invoke-Command -Session $Session -ScriptBlock { iex "sudo LD_LIBRARY_PATH=$(Split-Path $Using:Command -Parent)  $Using:Command $Using:ServerArgs" } -AsJob
    } else {
        $job = Invoke-Command -Session $Session -ScriptBlock { iex "$Using:Command $Using:ServerArgs"} -AsJob
    }
    # Poll the job for 10 seconds to see if it started.
    $stopWatch = [system.diagnostics.stopwatch]::StartNew()
    while ($stopWatch.ElapsedMilliseconds -lt 10000) {
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

# Passively starts the server on the remote machine by queuing up a new script to execute.
function Start-RemoteServerPassive {
    param ($Command)
    NetperfSendCommand $Command
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
            break
        }
    }
    Stop-Job -Job $Job | Out-Null
    $RemoteResult = Receive-Job -Job $Job -ErrorAction Ignore
    return $RemoteResult -join "`n"
}

function Wait-StartRemoteServerPassive {
    param ($FullPath, $RemoteName, $OutputDir, $UseSudo)

    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 5 | Out-Null
        Write-Host "Attempt $i to start the remote server, command: $FullPath -target:$RemoteName"
        $Process = Start-LocalTest $FullPath "-target:$RemoteName" $OutputDir $UseSudo
        $ConsoleOutput = Wait-LocalTest $Process $OutputDir $false 30000 $true
        Write-Host "Wait-StartRemoteServerPassive: $ConsoleOutput"
        $DidMatch = $ConsoleOutput -match "Completed" # Look for the special string to indicate success.
        if ($DidMatch) {
            return
        }
    }

    throw "Unable to start the remote server in time!"
}

# Creates a new local process to asynchronously run the test.
function Start-LocalTest {
    param ($FullPath, $FullArgs, $OutputDir, $UseSudo)
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    if ($isWindows) {
        $pinfo.FileName = $FullPath
        $pinfo.Arguments = $FullArgs
    } else {
        # We use bash to execute the test so we can collect core dumps.
        $NOFILE = Invoke-Expression "bash -c 'ulimit -n'"
        $CommonCommand = "ulimit -n $NOFILE && ulimit -c unlimited && LD_LIBRARY_PATH=$(Split-Path $FullPath -Parent) LSAN_OPTIONS=report_objects=1 ASAN_OPTIONS=disable_coredump=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $FullPath $FullArgs && echo ''"
        if ($UseSudo) {
            $pinfo.FileName = "/usr/bin/sudo"
            $pinfo.Arguments = "/usr/bin/bash -c `"$CommonCommand`""
        } else {
            $pinfo.FileName = "bash"
            $pinfo.Arguments = "-c `"$CommonCommand`""
        }
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

# Waits for a local test process to complete, and then returns the console output.
function Wait-LocalTest {
    param ($Process, $OutputDir, $testKernel, $TimeoutMs, $Silent = $false)
    $StdOut = $Process.StandardOutput.ReadToEndAsync()
    $StdError = $Process.StandardError.ReadToEndAsync()
    # Wait for the process to exit.
    if (!$Process.WaitForExit($TimeoutMs)) {
        # We timed out waiting for completion. Collect a dump of the current state.
        if ($testKernel) { Collect-LiveKD $OutputDir "client" }
        Collect-LocalDump $Process $OutputDir
        try { $Process.Kill() } catch { }
        try {
            [System.Threading.Tasks.Task]::WaitAll(@($StdOut, $StdError))
            $Out = $StdOut.Result.Trim()
            if ($Out.Length -ne 0) { Write-Host $Out }
        } catch {}
        if ($Silent) {
            Write-Host "Silently ignoring Client timeout!"
            return ""
        }
        throw "secnetperf: Client timed out!"
    }
    # Verify the process cleanly exitted.
    if ($Process.ExitCode -ne 0) {
        try {
            [System.Threading.Tasks.Task]::WaitAll(@($StdOut, $StdError))
            $Out = $StdOut.Result.Trim()
            if ($Out.Length -ne 0) { Write-Host $Out }
        } catch {}
        if ($Silent) {
            Write-Host "Silently ignoring Client exit code: $($Process.ExitCode)"
            return ""
        }
        throw "secnetperf: Nonzero exit code: $($Process.ExitCode)"
    }
    # Wait for the output streams to flush.
    [System.Threading.Tasks.Task]::WaitAll(@($StdOut, $StdError))
    $consoleTxt = $StdOut.Result.Trim()
    if ($consoleTxt.Length -eq 0) {
        if ($Silent) {
            Write-Host "Silently ignoring Client no console output!"
            return ""
        }
        throw "secnetperf: No console output (possibly crashed)!"
    }
    if ($consoleTxt.Contains("Error")) {
        if ($Silent) {
            Write-Host "Silently ignoring Client error: $($consoleTxt)"
            return ""
        }
        throw "secnetperf: $($consoleTxt.Substring(7))" # Skip over the "Error: " prefix
    }
    return $consoleTxt
}

# Test the args to see if they match one of the positive patterns but none of
# the negative patterns (prefixed by '-'). '?' matches any single character;
# '*' matches any substring; ';' separates two patterns.
function Check-TestFilter {
    param ($ExeArgs, $Filter)

    if (!$Filter) { return $true } # No filter means run everything

    $positivePatterns = $Filter.Split(';')
    $negativePatterns = $positivePatterns | Where-Object { $_ -like '-*' } | ForEach-Object { $_.TrimStart('-') }

    foreach ($pattern in $positivePatterns) {
        if ($pattern -like '-*') {
            continue
        }
        if ($ExeArgs -like $pattern) {
            foreach ($negativePattern in $negativePatterns) {
                if ($ExeArgs -like $negativePattern) {
                    return $false
                }
            }
            return $true
        }
    }

    return $false
}

# Parses the console output of secnetperf to extract the metric value.
function Get-TestOutput {
    param ($Output, $Metric)
    if ($Metric -eq "latency") {
        $latency_percentiles = "(?<=\d{1,3}(?:\.\d{1,2})?th: )\d+"
        $RPS_regex = "(?<=Result: )\d+"
        $percentiles = [regex]::Matches($Output, $latency_percentiles) | ForEach-Object {$_.Value}
        $rps = [regex]::Matches($Output, $RPS_regex) | ForEach-Object {$_.Value}
        $percentiles += $rps
        return $percentiles
    } elseif ($Metric -eq "hps") {
        $Output -match "(\d+) HPS" | Out-Null
        return $matches[1]
    } else { # throughput
        $Output -match "@ (\d+) kbps" | Out-Null
        return $matches[1]
    }
}

function Get-LatencyOutput {
    param ($FilePath)
    # The data is in the format of:
    #
    #       Value   Percentile   TotalCount 1/(1-Percentile)
    #
    #      93.000     0.000000            1         1.00
    #     118.000     0.100000        18203         1.11
    #     120.000     0.200000        29488         1.25
    #         ...          ...          ...          ...
    #    9847.000     0.999992       139772    131072.00
    #   41151.000     0.999993       139773    145635.56
    #   41151.000     1.000000       139773          inf
    ##[Mean    =      142.875, StdDeviation   =      137.790]
    ##[Max     =    41151.000, Total count    =       139773]
    ##[Buckets =            6, SubBuckets     =         2048]

    $contents = Get-Content $FilePath
    Remove-Item $FilePath

    # Parse through the data and extract the Value and Percentile columns and
    # convert to an array. Ignore the trailing data.
    $values = @()
    $percentiles = @()
    foreach ($line in $contents) {
        if ($line -match "^\s*(\d+\.\d+)\s+(\d+\.\d+)") {
            $values += [int]$matches[1]
            $percentiles += [double]$matches[2]
        }
    }

    return [pscustomobject]@{
        Values = $values
        Percentiles = $percentiles
    }
}

# Invokes secnetperf with the given arguments for both TCP and QUIC.
function Invoke-Secnetperf {
    param ($Session, $RemoteName, $RemoteDir, $UserName, $SecNetPerfPath, $LogProfile, $TestId, $ExeArgs, $io, $Filter, $Environment, $RunId, $SyncerSecret)

    $values = @(@(), @())
    $latency = $null
    $extraOutput = $null
    $hasFailures = $false
    if ($io -ne "xdp" -and $io -ne "qtip" -and $io -ne "wsk") {
        $tcpSupported = 1
    } else {
        $tcpSupported = 0
    }
    $metric = "throughput"
    if ($exeArgs.Contains("plat:1")) {
        $metric = "latency"
        $latency = @(@(), @())
        $extraOutput = Repo-Path "latency.txt"
        if (!$isWindows) {
            chmod +rw "$extraOutput"
        }
    } elseif ($exeArgs.Contains("prate:1")) {
        $metric = "hps"
    }

    for ($tcp = 0; $tcp -le $tcpSupported; $tcp++) {

    # Set up all the parameters and paths for running the test.
    $execMode = $ExeArgs.Substring(0, $ExeArgs.IndexOf(" ")) # First arg is the exec mode
    $clientPath = Repo-Path $SecNetPerfPath
    $serverArgs = "$execMode -io:$io"
    $clientArgs = "-target:$RemoteName $ExeArgs -tcp:$tcp -trimout -watchdog:25000"
    if ($io -eq "xdp" -or $io -eq "qtip") {
        $serverArgs += " -pollidle:10000"
        $clientArgs += " -pollidle:10000"
    }
    if ($io -eq "wsk") {
        $serverArgs += " -driverNamePriv:secnetperfdrvpriv"
        $clientArgs += " -driverNamePriv:secnetperfdrvpriv"
    }
    if ($metric -eq "throughput") {
        $serverArgs += " -stats:1"
        $clientArgs += " -pconn:1 -pstream:1"
    } elseif ($metric -eq "latency") {
        $serverArgs += " -stats:1"
        $clientArgs += " -pconn:1"
    }
    if ($extraOutput) {
        $clientArgs += " -extraOutputFile:$extraOutput"
    }

    if (!(Check-TestFilter $clientArgs $Filter)) {
        Write-Host "> secnetperf $clientArgs SKIPPED!"
        continue
    }

     # Linux XDP requires sudo for now
    $useSudo = (!$isWindows -and $io -eq "xdp")

    if ($tcp -eq 0) {
        $artifactName = "$TestId-quic"
    } else {
        $artifactName = "$TestId-tcp"
    }
    New-Item -ItemType Directory "artifacts/logs/$artifactName" -ErrorAction Ignore | Out-Null
    $artifactDir = Repo-Path "artifacts/logs/$artifactName"
    $remoteArtifactDir = "$RemoteDir/artifacts/logs/$artifactName"
    New-Item -ItemType Directory $artifactDir -ErrorAction Ignore | Out-Null
    if (!($Session -eq "NOT_SUPPORTED")) {
        Invoke-Command -Session $Session -ScriptBlock {
            New-Item -ItemType Directory $Using:remoteArtifactDir -ErrorAction Ignore | Out-Null
        }
    }

    $clientOut = (Join-Path $artifactDir "client.console.log")
    $serverOut = (Join-Path $artifactDir "server.console.log")

    # Start logging on both sides, if configured.
    if ($LogProfile -ne "" -and $LogProfile -ne "NULL" -and !($Session -eq "NOT_SUPPORTED")) {
        Invoke-Command -Session $Session -ScriptBlock {
            try { & "$Using:RemoteDir/scripts/log.ps1" -Cancel } catch {} # Cancel any previous logging
            & "$Using:RemoteDir/scripts/log.ps1" -Start -Profile $Using:LogProfile -ProfileInScriptDirectory
        }
        try { .\scripts\log.ps1 -Cancel } catch {} # Cancel any previous logging
        .\scripts\log.ps1 -Start -Profile $LogProfile
    }

    Write-Host "::group::> secnetperf $clientArgs"

    try {

    # Start the server running.
    "> secnetperf $serverArgs" | Add-Content $serverOut

    $StateDir = "C:/_state"
    if (!$isWindows) {
        $StateDir = "/etc/_state"
    }
    if ($Session -eq "NOT_SUPPORTED") {
        Start-RemoteServerPassive "$RemoteDir/$SecNetPerfPath $serverArgs"
        Wait-StartRemoteServerPassive "$clientPath" $RemoteName $artifactDir $useSudo
    } else {
        $job = Start-RemoteServer $Session "$RemoteDir/$SecNetPerfPath" $serverArgs $useSudo
    }

    # Run the test multiple times, failing (for now) only if all tries fail.
    # TODO: Once all failures have been fixed, consider all errors fatal.
    $successCount = 0
    $testFailures = $false
    for ($try = 0; $try -lt 3; $try++) {
        Write-Host "==============================`nRUN $($try+1):"
        "> secnetperf $clientArgs" | Add-Content $clientOut
        try {
            $process = Start-LocalTest "$clientPath" $clientArgs $artifactDir $useSudo
            $rawOutput = Wait-LocalTest $process $artifactDir ($io -eq "wsk") 30000
            Write-Host $rawOutput
            $values[$tcp] += Get-TestOutput $rawOutput $metric
            if ($extraOutput) {
                if ($useSudo) {
                    sudo chown $UserName $extraOutput
                }
                $latency[$tcp] += Get-LatencyOutput $extraOutput
            }
            $rawOutput | Add-Content $clientOut
            $successCount++
        } catch {
            Write-GHError $_
            #$testFailures = $true
        }
        Start-Sleep -Seconds 1 | Out-Null
    }
    if ($successCount -eq 0) {
        $testFailures = $true # For now, consider failure only if all failed
    }

    } catch {
        Write-GHError "Exception while running test case!"
        Write-GHError $_
        $_ | Format-List *
        $testFailures = $true
    } finally {
        # Stop the server.
        if ($Session -eq "NOT_SUPPORTED") {
            NetperfWaitServerFinishExecution -UnblockRoutine {
                $Socket = New-Object System.Net.Sockets.UDPClient
                $BytesToSend = @(
                    0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
                    0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c
                )
                $Socket.Send($BytesToSend, $BytesToSend.Length, $RemoteName, 9999) | Out-Null
                Write-Host "Sent special UDP packet to tell the server to die."
            }
        } else {
            try { Stop-RemoteServer $job $RemoteName | Add-Content $serverOut } catch { }
        }

        # Stop any logging and copy the logs to the artifacts folder.
        if ($LogProfile -ne "" -and $LogProfile -ne "NULL" -and $Session -ne "NOT_SUPPORTED") {
            try { .\scripts\log.ps1 -Stop -OutputPath "$artifactDir/client" -RawLogOnly }
            catch { Write-Host "Failed to stop logging on client!" }
            Invoke-Command -Session $Session -ScriptBlock {
                try { & "$Using:RemoteDir/scripts/log.ps1" -Stop -OutputPath "$Using:remoteArtifactDir/server" -RawLogOnly }
                catch { Write-Host "Failed to stop logging on server!" }
            }
            try { Copy-Item -FromSession $Session "$remoteArtifactDir/*" $artifactDir -Recurse }
            catch { Write-Host "Failed to copy server logs!" }
        }

        # Grab any crash dumps that were generated.
        if ($Session -ne "NOT_SUPPORTED") {
            if (Collect-LocalDumps $artifactDir) { }
            if (Collect-RemoteDumps $Session $artifactDir) {
                Write-GHError "Dump file(s) generated by server"
            }
        }
        Write-Host "::endgroup::"
        if ($testFailures) {
            $hasFailures = $true
            # Write outside the group to make it easier to find in the logs.
            Write-GHError "secnetperf: Test failures encountered!"
        }
    }}

    return [pscustomobject]@{
        Metric = $metric
        Values = $values
        Latency = $latency
        HasFailures = $hasFailures
    }
}

function CheckRegressionResult($values, $testid, $transport, $regressionJson, $envStr) {

    $sum = 0
    foreach ($item in $values) {
        $sum += $item
    }
    $avg = $sum / $values.Length
    $Testid = "$testid-$transport"

    $res = @{
        Baseline = "N/A"
        BestResult = "N/A"
        BestResultCommit = "N/A"
        CumulativeResult = "N/A"
        AggregateFunction = "N/A"
        HasRegression = $false
    }

    try {
        $res.Baseline = $regressionJson.$Testid.$envStr.baseline
        $res.BestResult = $regressionJson.$Testid.$envStr.BestResult
        $res.BestResultCommit = $regressionJson.$Testid.$envStr.BestResultCommit
        $res.CumulativeResult = $avg
        $res.AggregateFunction = "AVG"

        if ($avg -lt $res.Baseline) {
            Write-GHError "Regression detected in $Testid for $envStr. See summary table for details."
            $res.HasRegression = $true
        }
    } catch {
        Write-Host "Not using a watermark-based regression method. Skipping."
    }

    return $res
}

function CheckRegressionLat($values, $regressionJson, $testid, $transport, $envStr) {

    # TODO: Right now, we are not using a watermark based method for regression detection of latency percentile values because we don't know how to determine a "Best Ever" distribution.
    #       (we are just looking at P0, P50, P99 columns, and computing the baseline for each percentile as the mean - 2 * std of the last 20 runs. )
    #       So, the summary table omits a "BestEver" and "Baseline" column for latency. In fact, we ignore the "mean - 2*std" signal entirely. Need to determine how we compare distributions.

    $RpsAvg = 0
    $NumRuns = $values.Length / 9
    for ($offset = 0; $offset -lt $values.Length; $offset += 9) {
        $RpsAvg += $values[$offset + 8]
    }

    $RpsAvg /= $NumRuns
    $Testid = "$testid-$transport"

    $res = @{
        Baseline = "N/A"
        BestResult = "N/A"
        BestResultCommit = "N/A"
        CumulativeResult = "N/A"
        AggregateFunction = "N/A"
        HasRegression = $false
    }

    try {
        $res.Baseline = $regressionJson.$Testid.$envStr.baseline
        $res.BestResult = $regressionJson.$Testid.$envStr.BestResult
        $res.BestResultCommit = $regressionJson.$Testid.$envStr.BestResultCommit
        $res.CumulativeResult = $RpsAvg
        $res.AggregateFunction = "AVG"

        if ($RpsAvg -lt $res.Baseline) {
            Write-GHError "RPS Regression detected in $Testid for $envStr. See summary table for details."
            $res.HasRegression = $true
        }
    } catch {
        Write-Host "Not using a watermark-based regression method."
    }

    return $res
}
