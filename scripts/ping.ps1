<#

.SYNOPSIS
This script runs quicping locally.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Tls
    The TLS library use.

.PARAMETER KeepOutputOnSuccess
    Don't discard console output or logs on success.

.PARAMETER GenerateXmlResults
    Generates an xml Test report for the run.

.PARAMETER Debugger
    Attaches the debugger to the process.

.PARAMETER InitialBreak
    Debugger starts broken into the process to allow setting breakpoints, etc.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER Target
    A target to connect to.

.PARAMETER Listen
    An address to listen on or * for wildcard.

.PARAMETER Port
    A UDP port to connect to.

.PARAMETER Thumbprint
    The hash or thumbprint of the certificate to use.

.PARAMETER UnidirectionalStreams
    The number of unidirectional streams to open.

.PARAMETER PeerUnidirectionalStreams
    The number of unidirectional streams the peer is allowed to open.

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
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$KeepOutputOnSuccess = $false,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateXmlResults = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Debugger = $false,

    [Parameter(Mandatory = $false)]
    [switch]$InitialBreak = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [string]$Target = "",

    [Parameter(Mandatory = $false)]
    [string]$Listen = "",

    [Parameter(Mandatory = $false)]
    [UInt16]$Port = 0,

    [Parameter(Mandatory = $false)]
    [string]$Thumbprint = "",

    [Parameter(Mandatory = $false)]
    [uint]$UnidirectionalStreams = 0,

    [Parameter(Mandatory = $false)]
    [uint]$PeerUnidirectionalStreams = 0
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
$RunExecutable = Join-Path $RootDir "scripts/run-executable.ps1"

# Path to the quicping exectuable.
$QuicPing = $null
if ($IsWindows) {
    $QuicPing = Join-Path $RootDir "\artifacts\bin\windows\$($Arch)_$($Config)_$($Tls)\quicping.exe"
} else {
    $QuicPing = Join-Path $RootDir "/artifacts/bin/linux/$($Arch)_$($Config)_$($Tls)/quicping"
}

# Make sure the build is present.
if (!(Test-Path $QuicPing)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

# Build up all the arguments to pass to the Powershell script.
$Arguments = "-Path $($QuicPing) -ShowOutput"
if ($KeepOutputOnSuccess) {
    $Arguments += " -KeepOutputOnSuccess"
}
if ($GenerateXmlResults) {
    $Arguments += " -GenerateXmlResults"
}
if ($Debugger) {
    $Arguments += " -Debugger"
}
if ($InitialBreak) {
    $Arguments += " -InitialBreak"
}
if ("None" -ne $LogProfile) {
    $Arguments += " -LogProfile $($LogProfile)"
}

$ExtraArgs = ""
if ($Target -ne "") {
    $ExtraArgs += " -target:$Target"
}
if ($Listen -ne "") {
    $ExtraArgs += " -listen:$Listen"
}
if ($Port -ne 0) {
    $ExtraArgs += " -port:$Port"
}
if ($Thumbprint -ne "") {
    $ExtraArgs += " -thumbprint:$Thumbprint"
}
if ($UnidirectionalStreams -ne 0) {
    $ExtraArgs += " -uni:$UnidirectionalStreams"
}
if ($PeerUnidirectionalStreams -ne 0) {
    $ExtraArgs += " -peer_uni:$PeerUnidirectionalStreams"
}

if ($ExtraArgs -ne "") {
    $Arguments += " -Arguments `"$ExtraArgs`""
}

# Run the script.
Invoke-Expression ($RunExecutable + " " + $Arguments)
