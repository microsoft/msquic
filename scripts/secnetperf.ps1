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
    The full OS name and version being tested (i.e., ubuntu-20.04).

.PARAMETER arch
    The architecture being tested (i.e., x64).

.PARAMETER tls
    The TLS library being used (openssl or schannel). Not all libraries are supported on all platforms.

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
    [string]$RemoteName = "netperf-peer"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Set up some important paths.
$RemoteDir = "C:/_work/quic"
if (!$isWindows) {
    $RemoteDir = "/home/secnetperf/_work/quic"
}
$SecNetPerfDir = "artifacts/bin/$plat/$($arch)_Release_$tls"
$SecNetPerfPath = "$SecNetPerfDir/secnetperf"

# Set up the connection to the peer over remote powershell.
Write-Host "Connecting to $RemoteName..."
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
Write-Host "Killing any previous secnetperf on peer..."
Invoke-Command -Session $Session -ScriptBlock {
    Get-Process | Where-Object { $_.Name -eq "secnetperf" } | Stop-Process
}

# Copy the artifacts to the peer.
Write-Host "Copying files to peer..."
Invoke-Command -Session $Session -ScriptBlock {
    Remove-Item -Force -Recurse $Using:RemoteDir -ErrorAction Ignore | Out-Null
    mkdir $Using:RemoteDir | Out-Null
}
Copy-Item -ToSession $Session ./artifacts -Destination "$RemoteDir/artifacts" -Recurse
Copy-Item -ToSession $Session ./scripts -Destination "$RemoteDir/scripts" -Recurse
Copy-Item -ToSession $Session ./src/manifest/MsQuic.wprp -Destination "$RemoteDir/scripts"

$SQL = @"
INSERT OR IGNORE INTO Secnetperf_builds (Secnetperf_Commit, Build_date_time, TLS_enabled, Advanced_build_config)
VALUES ('$MsQuicCommit', '$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")', 1, 'TODO');
"@
$json = @{}
$allTests = @(
    "-exec:maxtput -up:10s -ptput:1",
    "-exec:maxtput -down:10s -ptput:1",
    "-exec:maxtput -rconn:1 -share:1 -conns:100 -run:10s -prate:1",
    "-exec:lowlat -rstream:1 -up:512 -down:4000 -run:10s -plat:1"
)
$env = $isWindows ? 1 : 2
$hasFailures = $false

try {

mkdir ./artifacts/logs | Out-Null

# Prepare the machines for the testing.
if ($isWindows) { # TODO: Run on Linux too?
    Write-Host "Preparing local machine for testing..."
    ./scripts/prepare-machine.ps1 -ForTest

    Write-Host "Preparing peer machine for testing..."
    Invoke-Command -Session $Session -ScriptBlock {
        iex "$Using:RemoteDir/scripts/prepare-machine.ps1 -ForTest"
    }
}

# Configure the dump collection.
Configure-DumpCollection $Session

if (!$isWindows) {
    # Make sure the secnetperf binary is executable.
    Write-Host "Updating secnetperf permissions..."
    Invoke-Command -Session $Session -ScriptBlock {
        $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$Using:RemoteDir/$Using:SecNetPerfDir"
        chmod +x "$Using:RemoteDir/$Using:SecNetPerfPath"
    }
    $fullPath = Join-Path (Split-Path $PSScriptRoot -Parent) $SecNetPerfDir
    $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$fullPath"
    chmod +x "./$SecNetPerfPath"

    if ((Get-Content "/etc/security/limits.conf") -notcontains "root soft core unlimited") {
        # Enable core dumps for the system.
        Write-Host "Setting core dump size limit..."
        sudo sh -c "echo 'root soft core unlimited' >> /etc/security/limits.conf"
        sudo sh -c "echo 'root hard core unlimited' >> /etc/security/limits.conf"
        sudo sh -c "echo '* soft core unlimited' >> /etc/security/limits.conf"
        sudo sh -c "echo '* hard core unlimited' >> /etc/security/limits.conf"
    }

    # Set the core dump pattern.
    Write-Host "Setting core dump pattern..."
    sudo sh -c "echo -n '%e.%p.%t.core' > /proc/sys/kernel/core_pattern"
}

# Run all the test cases.
Write-Host "Setup complete! Running all tests..."
for ($i = 0; $i -lt $allTests.Count; $i++) {
    $ExeArgs = $allTests[$i]
    $Output = Invoke-Secnetperf $Session $RemoteName $RemoteDir $SecNetPerfPath $LogProfile $ExeArgs
    $Test = $Output[-1]
    if ($Test.HasFailures) { $hasFailures = $true }

    # Process the results and add them to the SQL and JSON.
    $TestId = $i + 1
    $SQL += @"
`nINSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Kernel_mode, Run_arguments) VALUES ($TestId, 0, "$ExeArgs -tcp:0");
INSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Kernel_mode, Run_arguments) VALUES ($TestId, 0, "$ExeArgs -tcp:1");
"@

    for ($tcp = 0; $tcp -lt $Test.Values.Length; $tcp++) {
        $transport = $tcp -eq 1 ? "tcp" : "quic"
        foreach ($item in $Test.Values[$tcp]) {
            $json["$($Test.Metric)-$transport"] = $item
            if ($Test.Metric.startsWith("throughput")) {
                # Generate SQL statement. Assume LAST_INSERT_ROW_ID()
                $SQL += @"
`nINSERT INTO Secnetperf_test_runs (Secnetperf_test_ID, Secnetperf_commit, Client_environment_ID, Server_environment_ID, Result, Secnetperf_latency_stats_ID)
VALUES ($TestId, '$MsQuicCommit', $env, $env, $item, NULL);
"@
            }
        }
    }
}

Write-Host "Tests complete!"

if (Get-ChildItem -Path ./artifacts/logs -File -Recurse) {
    # Logs or dumps were generated. Copy the necessary symbols/files to the same
    # direcotry be able to open them.
    Write-Host "Copying debuggig files to logs directory..."
    if ($isWindows) {
        Copy-Item "$SecNetPerfDir/*.pdb" ./artifacts/logs
    } else {
        Copy-Item "$SecNetPerfDir/libmsquic.so" ./artifacts/logs
        Copy-Item "$SecNetPerfDir/secnetperf" ./artifacts/logs
    }
}

} catch {
    Write-GHError "Exception while running tests!"
    Write-GHError $_
    Get-Error
    $_ | Format-List *
    $hasFailures = $true
} finally {
    # Save the test results (sql and json).
    Write-Host "`Writing test-results-$plat-$os-$arch-$tls.sql..."
    $SQL | Set-Content -Path "test-results-$plat-$os-$arch-$tls.sql"

    Write-Host "`Writing json-test-results-$plat-$os-$arch-$tls.json..."
    $json | ConvertTo-Json | Set-Content -Path "json-test-results-$plat-$os-$arch-$tls.json"
}

if ($hasFailures) {
    exit 1
}
