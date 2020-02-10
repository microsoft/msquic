<#

.SYNOPSIS
This script runs spinquic locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Tls
    The TLS library use.

.PARAMETER Timeout
    The run time in milliseconds.

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
    [string]$Tls = "schannel",

    [Parameter(Mandatory = $false)]
    [Int32]$Timeout = 60000,

    [Parameter(Mandatory = $false)]
    [switch]$KeepOutputOnSuccess = $false,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateXmlResults = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Debugger = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$ConvertLogs = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Path to the run-executable Powershell script.
$RunExecutable = Join-Path $PSScriptRoot ".azure/scripts/run-executable.ps1"

# Path to the spinquic exectuable.
$SpinQuic = $null
if ($IsWindows) {
    $SpinQuic = Join-Path $PSScriptRoot "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\spinquic.exe"
} else {
    $SpinQuic = Join-Path $PSScriptRoot "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/spinquic"
}

# Build up all the arguments to pass to the Powershell script.
$Arguments = "-Path $($SpinQuic) -Arguments 'both -timeout:$($Timeout)' -ShowOutput"
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

# Run the script.
Invoke-Expression ($RunExecutable + " " + $Arguments)
