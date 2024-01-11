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

# Set up some important paths.
$RemoteDir = "C:/_work/quic"
if (!$isWindows) {
    $RemoteDir = "/home/secnetperf/_work/quic"
}
$SecNetPerfDir = "artifacts/bin/$plat/$($arch)_Release_$tls"
$SecNetPerfPath = "$SecNetPerfDir/secnetperf"

# Set up the connection to the peer over remote powershell.
Write-Output "Connecting to $RemoteName..."

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
Write-Output "Killing any previous secnetperf on peer..."
Invoke-Command -Session $Session -ScriptBlock {
    Get-Process | Where-Object { $_.Name -eq "secnetperf" } | Stop-Process
}

# Copy the artifacts to the peer.
Write-Output "Copying files to peer..."
Invoke-Command -Session $Session -ScriptBlock {
    Remove-Item -Force -Recurse $Using:RemoteDir -ErrorAction Ignore | Out-Null
    mkdir $Using:RemoteDir | Out-Null
}
Copy-Item -ToSession $Session ./artifacts -Destination "$RemoteDir/artifacts" -Recurse
Copy-Item -ToSession $Session ./scripts -Destination "$RemoteDir/scripts" -Recurse
Copy-Item -ToSession $Session ./src/manifest/MsQuic.wprp -Destination "$RemoteDir/scripts"
Invoke-Command -Session $Session -ScriptBlock {
    dir "$Using:RemoteDir/scripts"
}

$encounterFailures = $false

try {

mkdir .\artifacts\logs | Out-Null

# Prepare the machines for the testing.
if ($isWindows) { # TODO: Run on Linux too?
    Write-Output "Preparing local machine for testing..."
    .\scripts\prepare-machine.ps1 -ForTest

    Write-Output "Preparing peer machine for testing..."
    Invoke-Command -Session $Session -ScriptBlock {
       & "$Using:RemoteDir/scripts/prepare-machine.ps1 -ForTest"
    }
}

if (!$isWindows) {
    # Make sure the secnetperf binary is executable.
    Write-Output "Updating secnetperf permissions..."
    Invoke-Command -Session $Session -ScriptBlock {
        $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$Using:RemoteDir/$Using:SecNetPerfDir"
        chmod +x "$Using:RemoteDir/$Using:SecNetPerfPath"
    }
    $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:./$RemoteDir/$SecNetPerfDir"
    chmod +x "./$RemoteDir/$SecNetPerfPath"
}

# Logging to collect quic traces while running the tests.
# if ($LogProfile -ne "" -and $LogProfile -ne "NULL") { # TODO: Linux back slash works?
#     Write-Output "Starting logging with log profile: $LogProfile..."
#     .\scripts\log.ps1 -Start -Profile $LogProfile
# }

# Run secnetperf on the server.
Write-Output "Starting secnetperf server..."
$Job = Start-RemoteServer $Session "$RemoteDir/$SecNetPerfPath -exec:maxtput"
if ($null -eq $Job) {
    throw "Server failed to start!"
}

# Run secnetperf on the client.
Write-Output "Running tests on the client..."

$PSDefaultParameterValues["Disabled"] = $true

####################################################################################################

    # TEST EXECUTION

####################################################################################################

$SQL = @"

INSERT OR IGNORE INTO Secnetperf_builds (Secnetperf_Commit, Build_date_time, TLS_enabled, Advanced_build_config)
VALUES ('$MsQuicCommit', '$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")', 1, 'TODO');

INSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Secnetperf_build_ID, Kernel_mode, Run_arguments, Test_name)
VALUES ('throughput-upload-quic-$MsQuicCommit', '$MsQuicCommit', 0, '-target:netperf-peer -exec:maxtput -upload:10s', 'throughput-upload-quic');

INSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Secnetperf_build_ID, Kernel_mode, Run_arguments, Test_name)
VALUES ('throughput-upload-tcp-$MsQuicCommit', '$MsQuicCommit', 0, '-target:netperf-peer -exec:maxtput -upload:10s -tcp:1', 'throughput-upload-tcp');

INSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Secnetperf_build_ID, Kernel_mode, Run_arguments, Test_name)
VALUES ('throughput-download-quic-$MsQuicCommit', '$MsQuicCommit', 0, '-target:netperf-peer -exec:maxtput -download:10s', 'throughput-download-quic');

INSERT OR IGNORE INTO Secnetperf_tests (Secnetperf_test_ID, Secnetperf_build_ID, Kernel_mode, Run_arguments, Test_name)
VALUES ('throughput-download-tcp-$MsQuicCommit', '$MsQuicCommit', 0, '-target:netperf-peer -exec:maxtput -download:10s -tcp:1', 'throughput-download-tcp');

"@

$exe = "./$RemoteDir/$SecNetPerfPath"

$json = @{}

$maxtputIds = @(
    "throughput-upload",
    "throughput-download",
    "hps"
)

$lowlatIds = @(
    "rps-1conn-1stream"
)

$maxtput = @(
    "-exec:maxtput -up:10s -ptput:1",
    "-exec:maxtput -down:10s -ptput:1",
    "-exec:maxtput -rconn:1 -share:1 -conns:100 -run:10s -prate:1"
)

$lowlat = @(
    "-exec:lowlat -rstream:1 -up:512 -down:4000 -run:10s -plat:1"
)

$SQL += Invoke-SecnetperfTest $maxtputIds $maxtput $exe $json $LogProfile

# Start and restart the SecNetPerf server without maxtput.
Write-Host "Restarting server without maxtput..."
Write-Host "`nStopping server. Server Output:"
$RemoteResults = Stop-RemoteServer $Job
Write-Host $RemoteResults.ToString()

Write-Host "Starting server back up again..."
$Job = Start-RemoteServer $Session "$RemoteDir/$SecNetPerfPath -exec:lowlat"
if ($null -eq $Job) {
    throw "Server failed to start!"
}

$SQL += Invoke-SecnetperfTest $lowlatIds $lowlat $exe $json $LogProfile

####################################################################################################

    # END TEST EXECUTION

####################################################################################################

# Kill the server process.
Write-Output "`nStopping server. Server Output:"
$RemoteResults = Stop-RemoteServer $Job
Write-Output $RemoteResults.ToString()

# if ($LogProfile -ne "" -and $LogProfile -ne "NULL") { # TODO: Linux back slash works?
#     Write-Output "Stopping logging..."
#     .\scripts\log.ps1 -Stop -OutputPath .\artifacts\logs\quic
# }

# Save the test results (sql and json).
Write-Output "`nWriting test-results-$plat-$os-$arch-$tls.sql..."
$SQL | Set-Content -Path "test-results-$plat-$os-$arch-$tls.sql"

Write-Output "`nWriting json-test-results-$plat-$os-$arch-$tls.json..."
$json | ConvertTo-Json | Set-Content -Path "json-test-results-$plat-$os-$arch-$tls.json"

} catch {
    Write-GHError "Exception occurred while running tests..."
    Write-GHError $_
    $encounterFailures = $true
} finally {
    # TODO: Do any further book keeping here.
}

if ($encounterFailures) {
    exit 1
}
