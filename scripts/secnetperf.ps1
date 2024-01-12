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

$encounterFailures = $false

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

if (!$isWindows) {
    # Make sure the secnetperf binary is executable.
    Write-Host "Updating secnetperf permissions..."
    Invoke-Command -Session $Session -ScriptBlock {
        $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$Using:RemoteDir/$Using:SecNetPerfDir"
        chmod +x "$Using:RemoteDir/$Using:SecNetPerfPath"
    }
    $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:./$SecNetPerfDir"
    chmod +x "./$SecNetPerfPath"
}

$PSDefaultParameterValues["Disabled"] = $true # TODO: Why?

$SQL = @"

INSERT OR IGNORE INTO Secnetperf_builds (Secnetperf_Commit, Build_date_time, TLS_enabled, Advanced_build_config)
VALUES ('$MsQuicCommit', '$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")', 1, 'TODO');

"@

$json = @{}

$exeArgs = @(
    "-exec:maxtput -up:10s -ptput:1",
    "-exec:maxtput -down:10s -ptput:1",
    "-exec:maxtput -rconn:1 -share:1 -conns:100 -run:10s -prate:1",
    "-exec:lowlat -rstream:1 -up:512 -down:4000 -run:10s -plat:1"
)

for ($i = 0; $i -lt $exeArgs.Count; $i++) {
    $res = Invoke-Secnetperf $Session $RemoteName $RemoteDir $SecNetPerfPath $LogProfile $exeArgs[$i] $MsQuicCommit $i
    $SQL += $res[0]
    $json += $res[1]
    if ($res[2]) { $encounterFailures = $true }
}

# Save the test results (sql and json).
Write-Host "`Writing test-results-$plat-$os-$arch-$tls.sql..."
$SQL | Set-Content -Path "test-results-$plat-$os-$arch-$tls.sql"

Write-Host "`Writing json-test-results-$plat-$os-$arch-$tls.json..."
$json | ConvertTo-Json | Set-Content -Path "json-test-results-$plat-$os-$arch-$tls.json"

} catch {
    Write-GHError "Exception occurred!"
    Write-GHError $_
    $encounterFailures = $true
} finally {
    # TODO: Do any further book keeping here.
}

if ($encounterFailures) {
    exit 1
}
