<#

.SYNOPSIS
This script runs quicinterop locally.

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

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER ConvertLogs
    Convert any collected logs to text. Only works when LogProfile is set.

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
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$ConvertLogs = $false
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

# Path to the quicinterop exectuable.
$QuicInterop = $null
if ($IsWindows) {
    $QuicInterop = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\quicinterop.exe"
} else {
    $QuicInterop = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/quicinterop"
}

# Make sure the build is present.
if (!(Test-Path $QuicInterop)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

# Build up all the arguments to pass to the Powershell script.
$Arguments = "-Path $($QuicInterop) -ShowOutput"
if ($KeepOutputOnSuccess) {
    $Arguments += " -KeepOutputOnSuccess"
}
if ($GenerateXmlResults) {
    $Arguments += " -GenerateXmlResults"
}
if ($Debugger) {
    $Arguments += " -Debugger"
}
if ("None" -ne $LogProfile) {
    $Arguments += " -LogProfile $($LogProfile)"
}
if ($ConvertLogs) {
    $Arguments += " -ConvertLogs"
}
$Arguments += " -Arch $Arch"

# Run the script.
Invoke-Expression ($RunExecutable + " " + $Arguments)
