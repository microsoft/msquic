<#

NOTE:

This script assumes the latest MsQuic commit is built and downloaded as artifacts in the current session.

.PARAMETER LogProfile
    Configures the logging scope for the test. None by default.

.PARAMETER MsQuicCommit
    The MsQuic commit to use for the test. Defaults to "manual" which means the latest commit built and downloaded as artifacts in the current session.

.PARAMETER plat
    The platform (linux or windows) this test is running on.

.PARAMETER os
    The full OS name and version being tested (i.e., ubuntu-22.04).

.PARAMETER arch
    The architecture being tested (i.e., x64).

.PARAMETER tls
    The TLS library being used (openssl or schannel). Not all libraries are supported on all platforms.

.PARAMETER io
    The network IO interface to be used (not all are supported on all platforms).

.PARAMETER filter
    Run only the tests whose arguments match one of the positive patterns but
    none of the negative patterns (prefixed by '-'). '?' matches any single
    character; '*' matches any substring; ';' separates two patterns.

#>

# Import the helper module.
Using module .\secnetperf-helpers.psm1

param (
    [ValidateSet("", "NULL", "Basic.Light", "Datapath.Light", "Datapath.Verbose", "Stacks.Light", "Stacks.Verbose", "RPS.Light", "RPS.Verbose", "Performance.Light", "Basic.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light", "SpinQuicWarnings.Light")]
    [string]$LogProfile = "",

    [Parameter(Mandatory = $true)]
    [string]$MsQuicCommit = "manual",

    [Parameter(Mandatory = $true)]
    [ValidateSet("windows", "linux")]
    [string]$plat = "windows",

    [Parameter(Mandatory = $true)]
    [string]$os = "windows-2022",

    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "arm64")]
    [string]$arch = "x64",

    [Parameter(Mandatory = $true)]
    [ValidateSet("openssl", "openssl3", "schannel")]
    [string]$tls = "schannel",

    [Parameter(Mandatory = $false)]
    [ValidateSet("", "iocp", "rio", "xdp", "qtip", "wsk", "epoll", "kqueue")]
    [string]$io = "",

    [Parameter(Mandatory = $false)]
    [string]$filter = "",

    [Parameter(Mandatory = $false)]
    [string]$RemoteName = "netperf-peer"
)

Set-StrictMode -Version "Latest"
$PSDefaultParameterValues["*:ErrorAction"] = "Stop"

# Set up some important paths.
$RemoteDir = "C:/_work/quic"
if (!$isWindows) {
    $RemoteDir = "/home/secnetperf/_work/quic"
}
$SecNetPerfDir = "artifacts/bin/$plat/$($arch)_Release_$tls"
$SecNetPerfPath = "$SecNetPerfDir/secnetperf"
if ($io -eq "") {
    if ($isWindows) {
        $io = "iocp"
    } else {
        $io = "epoll"
    }
}

# Set up the connection to the peer over remote powershell.
Write-Host "Connecting to $RemoteName"
if ($isWindows) {
    $Session = New-PSSession -ComputerName $RemoteName -ConfigurationName PowerShell.7
} else {
    $Session = New-PSSession -HostName $RemoteName -UserName secnetperf -SSHTransport
}
if ($null -eq $Session) {
    Write-GHError "Failed to create remote session"
    exit 1
}

# Make sure nothing is running from a previous run.
Cleanup-State $Session $RemoteDir

if ($io -eq "wsk") {
    # WSK also needs the kernel mode binaries in the usermode path.
    Write-Host "Moving kernel binaries to usermode path"
    $KernelDir = "artifacts/bin/winkernel/$($arch)_Release_$tls"
    Copy-Item "$KernelDir/secnetperfdrvpriv.sys" $SecNetPerfDir
    Copy-Item "$KernelDir/secnetperfdrvpriv.pdb" $SecNetPerfDir
    Copy-Item "$KernelDir/msquicpriv.sys" $SecNetPerfDir
    Copy-Item "$KernelDir/msquicpriv.pdb" $SecNetPerfDir
    # Remove all the other kernel binaries since we don't need them any more.
    Remove-Item -Force -Recurse $KernelDir | Out-Null
}

# Copy the artifacts to the peer.
Write-Host "Copying files to peer"
Invoke-Command -Session $Session -ScriptBlock {
    if (Test-Path $Using:RemoteDir) {
        Remove-Item -Force -Recurse $Using:RemoteDir | Out-Null
    }
    mkdir $Using:RemoteDir | Out-Null
}
Copy-Item -ToSession $Session ./artifacts -Destination "$RemoteDir/artifacts" -Recurse
Copy-Item -ToSession $Session ./scripts -Destination "$RemoteDir/scripts" -Recurse
Copy-Item -ToSession $Session ./src/manifest/MsQuic.wprp -Destination "$RemoteDir/scripts"

$SQL = @"
INSERT OR IGNORE INTO Secnetperf_builds (Secnetperf_Commit, Build_date_time, TLS_enabled, Advanced_build_config)
VALUES ("$MsQuicCommit", "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")", 1, "TODO");
"@
$json = @{}

$allTests = [System.Collections.Specialized.OrderedDictionary]::new()

# > All tests:
$allTests["tput-up"] = "-exec:maxtput -up:12s -ptput:1"
$allTests["tput-down"] = "-exec:maxtput -down:12s -ptput:1"
$allTests["hps-conns-100"] = "-exec:maxtput -rconn:1 -share:1 -conns:100 -run:12s -prate:1"
$allTests["rps-up-512-down-4000"] = "-exec:lowlat -rstream:1 -up:512 -down:4000 -run:20s -plat:1"

$env = $isWindows ? 1 : 2
$hasFailures = $false

try {

mkdir ./artifacts/logs | Out-Null

# Prepare the machines for the testing.
if ($isWindows) {
    Write-Host "Preparing local machine for testing"
    ./scripts/prepare-machine.ps1 -ForTest -InstallSigningCertificates

    Write-Host "Preparing peer machine for testing"
    Invoke-Command -Session $Session -ScriptBlock {
        & "$Using:RemoteDir/scripts/prepare-machine.ps1" -ForTest -InstallSigningCertificates
    }

    $HasTestSigning = $false
    try { $HasTestSigning = ("$(bcdedit)" | Select-String -Pattern "testsigning\s+Yes").Matches.Success } catch { }
    if (!$HasTestSigning) { Write-Host "Test Signing Not Enabled!" }
}

# Configure the dump collection.
Configure-DumpCollection $Session

# Install any dependent drivers.
if ($io -eq "xdp") { Install-XDP $Session $RemoteDir }
if ($io -eq "wsk") { Install-Kernel $Session $RemoteDir $SecNetPerfDir }

if (!$isWindows) {
    # Make sure the secnetperf binary is executable.
    Write-Host "Updating secnetperf permissions"
    Invoke-Command -Session $Session -ScriptBlock {
        $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$Using:RemoteDir/$Using:SecNetPerfDir"
        chmod +x "$Using:RemoteDir/$Using:SecNetPerfPath"
    }
    $fullPath = Repo-Path $SecNetPerfDir
    $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$fullPath"
    chmod +x "./$SecNetPerfPath"

    if ((Get-Content "/etc/security/limits.conf") -notcontains "root soft core unlimited") {
        # Enable core dumps for the system.
        Write-Host "Setting core dump size limit"
        sudo sh -c "echo "root soft core unlimited" >> /etc/security/limits.conf"
        sudo sh -c "echo "root hard core unlimited" >> /etc/security/limits.conf"
        sudo sh -c "echo "* soft core unlimited" >> /etc/security/limits.conf"
        sudo sh -c "echo "* hard core unlimited" >> /etc/security/limits.conf"
    }

    # Set the core dump pattern.
    Write-Host "Setting core dump pattern"
    sudo sh -c "echo -n "%e.client.%p.%t.core" > /proc/sys/kernel/core_pattern"
}

# Run all the test cases.
Write-Host "Setup complete! Running all tests"
foreach ($testId in $allTests.Keys) {
    $ExeArgs = $allTests[$testId] + " -io:$io"
    $Output = Invoke-Secnetperf $Session $RemoteName $RemoteDir $SecNetPerfPath $LogProfile $testId $ExeArgs $io $filter
    $Test = $Output[-1]
    if ($Test.HasFailures) { $hasFailures = $true }

    # Process the results and add them to the SQL and JSON.
    $SQL += @"
`nINSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Kernel_mode, Run_arguments) VALUES ("$TestId-tcp-0", 0, "$ExeArgs -tcp:0");
INSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Kernel_mode, Run_arguments) VALUES ("$TestId-tcp-1", 0, "$ExeArgs -tcp:1");
"@

    for ($tcp = 0; $tcp -lt $Test.Values.Length; $tcp++) {
        if ($Test.Values[$tcp].Length -eq 0) { continue }
        $transport = $tcp -eq 1 ? "tcp" : "quic"
        $json["$testId-$transport"] = $Test.Values[$tcp]
        if ($Test.Metric -eq "throughput") {
            foreach ($item in $Test.Values[$tcp]) {
                $SQL += @"
`nINSERT INTO Secnetperf_test_runs (Secnetperf_test_ID, Secnetperf_commit, Client_environment_ID, Server_environment_ID, Result, Secnetperf_latency_stats_ID, io, tls)
VALUES ("$TestId-tcp-$tcp", "$MsQuicCommit", $env, $env, $item, NULL, "$io", "$tls");
"@
            }
        } elseif ($Test.Metric -eq "latency") {
            # Test.Values[...] is a flattened 1D array of the form: [ first run + RPS, second run + RPS, third run + RPS..... ], ie. if each run has 8 values + RPS, then the array has 27 elements (8*3 + 3)
            for ($offset = 0; $offset -lt $Test.Values[$tcp].Length; $offset += 9) {
                $SQL += @"
`nINSERT INTO Secnetperf_latency_stats (p0, p50, p90, p99, p999, p9999, p99999, p999999)
VALUES ($($Test.Values[$tcp][$offset]), $($Test.Values[$tcp][$offset+1]), $($Test.Values[$tcp][$offset+2]), $($Test.Values[$tcp][$offset+3]), $($Test.Values[$tcp][$offset+4]), $($Test.Values[$tcp][$offset+5]), $($Test.Values[$tcp][$offset+6]), $($Test.Values[$tcp][$offset+7]));
INSERT INTO Secnetperf_test_runs (Secnetperf_test_ID, Secnetperf_commit, Client_environment_ID, Server_environment_ID, Result, Secnetperf_latency_stats_ID, io, tls)
VALUES ("$TestId-tcp-$tcp", "$MsQuicCommit", $env, $env, $($Test.Values[$tcp][$offset+8]), LAST_INSERT_ROWID(), "$io", "$tls");
"@
            }
        }
    }
}

Write-Host "Tests complete!"

} catch {
    Write-GHError "Exception while running tests!"
    Write-GHError $_
    Get-Error
    $_ | Format-List *
    $hasFailures = $true
} finally {

    # Perform any necessary cleanup.
    try { Cleanup-State $Session $RemoteDir } catch { }

    try {
        if (Get-ChildItem -Path ./artifacts/logs -File -Recurse) {
            # Logs or dumps were generated. Copy the necessary symbols/files to
            # the same direcotry be able to open them.
            Write-Host "Copying debugging files to logs directory"
            if ($isWindows) {
                Copy-Item "$SecNetPerfDir/*.pdb" ./artifacts/logs
            } else {
                Copy-Item "$SecNetPerfDir/libmsquic.so" ./artifacts/logs
                Copy-Item "$SecNetPerfDir/secnetperf" ./artifacts/logs
            }
        }
    } catch { }

    # Save the test results (sql and json).
    Write-Host "`Writing test-results-$plat-$os-$arch-$tls-$io.sql"
    $SQL | Set-Content -Path "test-results-$plat-$os-$arch-$tls-$io.sql"
    Write-Host "`Writing json-test-results-$plat-$os-$arch-$tls-$io.json"
    $json | ConvertTo-Json | Set-Content -Path "json-test-results-$plat-$os-$arch-$tls-$io.json"
}

# Clear out any exit codes from previous commands.
$global:LastExitCode = 0

if ($hasFailures) {
    exit 1
}
