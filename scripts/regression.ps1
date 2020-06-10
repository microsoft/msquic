<#

.SYNOPSIS
This script runs spinquic locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Tls
    The TLS library use.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Path to the run-executable Powershell script.
$RunExecutable = Join-Path $RootDir ".azure/scripts/run-executable.ps1"

# Path to the spinquic exectuable.
$PingClient = $null
if ($IsWindows) {
    $PingClient = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\quicping.exe"
} else {
    $PingClient = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/quicping"
}

# Make sure the build is present.
if (!(Test-Path $PingClient)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

# Build up all the arguments to pass to the Powershell script.
$Arguments = "-Path $($PingClient) -Arguments '-target:localhost -uni:1 -length:100000000' -ShowOutput"

$LogPath = Join-Path $RootDir "artifacts/regressions/logs"

$ServerLogPath = Join-Path $LogPath "ServerPingLog.txt"
$ClientLogPath = Join-Path $LogPath "ClientPingLog.txt"

$proc = Start-Process -NoNewWindow $PingClient "-listen:* -thumbprint:41A3E100CD61CFCE8DCC79FC1973CE1ECFE87747 -peer_uni:1" -RedirectStandardInput  $ServerLogPath -PassThru 

Write-Host $proc

Start-Sleep 1

# Run the script.
Invoke-Expression ($RunExecutable + " " + $Arguments)

$proc.Kill()
