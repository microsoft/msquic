param(
    [Parameter(Mandatory = $true)]
    [string] $Command,

    [Parameter(Mandatory = $false)]
    [string] $WorkingDir = "."
)

if ($PSVersionTable.PSVersion.Major -lt 7) {
    $IsWindows = $true
}

function SetLinuxLibPath {
    $fullPath = "./artifacts/bin/linux/x64_Release_quictls"
    $SecNetPerfPath = "$fullPath/secnetperf"
    $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$fullPath"
    chmod +x "$SecNetPerfPath"
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


$mode = "maxtput"
$io = "iocp"
$stats = "0"
$env:linux_perf_prefix = ""

if ($Command.Contains("lowlat")) {
    $mode = "lowlat"
}

if ($Command.Contains("epoll")) {
    $io = "epoll"
}

if ($Command.Contains("iouring")) {
    $io = "iouring"
}

if ($Command.Contains("xdp")) {
    $io = "xdp"
}

if ($Command.Contains("wsk")) {
    $io = "wsk"
}

if ($Command.Contains("stats")) {
    $stats = "1"
}

function Repo-Path {
    param ($Path)
    return Join-Path (Split-Path $PSScriptRoot -Parent) $Path
}

if ($Command.Contains("/home/secnetperf/_work/quic/artifacts/bin/linux/x64_Release_quictls/secnetperf")) {
    Write-Host "Executing command: $(pwd)/artifacts/bin/linux/x64_Release_quictls/secnetperf -exec:$mode -io:$io -stats:$stats"
    SetLinuxLibPath

    # Check and see if a 'perf_command.txt' file exists. If it does, then we need to prepend the command with the contents of the file.
    if (Test-Path "perf_command.txt") {
        Write-Host "Found 'perf_command.txt' file. Prepending the command with the contents of the file."
        $perf_command = Get-Content "perf_command.txt"
        Write-Host "Prepending the command with: $perf_command"
        $env:linux_perf_prefix = $perf_command
    }
    Write-Host "About to invoke the expression: $env:linux_perf_prefix./artifacts/bin/linux/x64_Release_quictls/secnetperf -exec:$mode -io:$io -stats:$stats"
    Invoke-Expression "$env:linux_perf_prefix./artifacts/bin/linux/x64_Release_quictls/secnetperf -exec:$mode -io:$io -stats:$stats"

} elseif ($Command.Contains("C:/_work/quic/artifacts/bin/windows/x64_Release_schannel/secnetperf")) {
    Write-Host "Executing command: $(pwd)/artifacts/bin/windows/x64_Release_schannel/secnetperf -exec:$mode -io:$io -stats:$stats"
    ./artifacts/bin/windows/x64_Release_schannel/secnetperf -exec:$mode -io:$io -stats:$stats
} elseif ($Command.Contains("Prepare_MachineForTest")) {
    Write-Host "Executing command: $WorkingDir\scripts\prepare-machine.ps1 -ForTest -InstallSigningCertificates"
    Invoke-Expression "$WorkingDir\scripts\prepare-machine.ps1 -ForTest -InstallSigningCertificates"
} elseif ($Command.Contains("Install_XDP")) {
    Write-Host "Executing command: Install_XDP"
    .\scripts\prepare-machine.ps1 -InstallXdpDriver
} elseif ($Command -eq "Install_Kernel") {
    Write-Host "Executing command: Install_Kernel"
    $KernelDir = Repo-Path "./artifacts/bin/winkernel/x64_Release_schannel"
    $SecNetPerfDir = Repo-Path "./artifacts/bin/windows/x64_Release_schannel"
    if (Test-Path $KernelDir) {
        # WSK also needs the kernel mode binaries in the usermode path.
        Write-Host "Moving kernel binaries to usermode path"
        Write-Host "Kernel directory: $KernelDir, Usermode directory: $SecNetPerfDir"
        Copy-Item "$KernelDir/secnetperfdrvpriv.sys" $SecNetPerfDir
        Copy-Item "$KernelDir/secnetperfdrvpriv.pdb" $SecNetPerfDir
        Copy-Item "$KernelDir/msquicpriv.sys" $SecNetPerfDir
        Copy-Item "$KernelDir/msquicpriv.pdb" $SecNetPerfDir
        # Remove all the other kernel binaries since we don't need them any more.
        Remove-Item -Force -Recurse $KernelDir | Out-Null
    } else {
        throw "Did not find kernel directory: $KernelDir"
    }
    $localSysPath = "$SecNetPerfDir/msquicpriv.sys"
    if (!(Test-Path $localSysPath)) {
        throw "Did not find kernel driver: $localSysPath"
    }
    Write-Host "(SERVER) Installing Kernel driver. Path: $localSysPath"
    sc.exe create "msquicpriv" type= kernel binpath= $localSysPath start= demand | Out-Null
    net.exe start msquicpriv
} elseif ($Command.Contains("Start_Server_Msquic_Logging")) {
    $LogProfile = $Command.Split(";")[1]
    .\scripts\log.ps1 -Start -Profile $LogProfile
} elseif ($Command.Contains("Stop_Server_Msquic_Logging")) {
    $artifactName = $Command.Split(";")[1]
    # if artifacts don't exist, make it
    New-Item -ItemType Directory "artifacts/logs/$artifactName/server" -ErrorAction Ignore | Out-Null
    .\scripts\log.ps1 -Stop -OutputPath "artifacts/logs/$artifactName/server" -RawLogOnly
} elseif ($Command.Contains("Config_DumpCollection_Windows")) {
    $DumpDir = "C:/_work/quic/artifacts/crashdumps"
    $WerDumpRegPath = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\secnetperf.exe"
    New-Item -Path $DumpDir -ItemType Directory -ErrorAction Ignore | Out-Null
    New-Item -Path $WerDumpRegPath -Force -ErrorAction Ignore | Out-Null
    Set-ItemProperty -Path $WerDumpRegPath -Name DumpFolder -Value $DumpDir | Out-Null
    Set-ItemProperty -Path $WerDumpRegPath -Name DumpType -Value 2 | Out-Null
} else {
    throw "Invalid command: $Command"
}
