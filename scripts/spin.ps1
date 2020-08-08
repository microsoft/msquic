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

.Parameter RepeatCount
    The amount of times to repeat the full test

.PARAMETER KeepOutputOnSuccess
    Don't discard console output or logs on success.

.PARAMETER GenerateXmlResults
    Generates an xml Test report for the run.

.PARAMETER Debugger
    Attaches the debugger to the process.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

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
    [Int32]$Timeout = 60000,

    [Parameter(Mandatory = $false)]
    [Int32]$RepeatCount = 1,

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
    [switch]$CodeCoverage = $false
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

#Validate the code coverage switch.
if ($CodeCoverage) {
    if (!$IsWindows) {
        Write-Error "-CodeCoverage switch only supported on Windows";
    }
    if ($Debugger) {
        Write-Error "-CodeCoverage switch is not supported with debugging";
    }
    if (!(Test-Path "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe")) {
        Write-Error "Code coverage tools are not installed";
    }
}

# Path to the spinquic exectuable.
$SpinQuic = $null
if ($IsWindows) {
    $SpinQuic = Join-Path $RootDir "\artifacts\bin\windows\$($Arch)_$($Config)_$($Tls)\spinquic.exe"
} else {
    $SpinQuic = Join-Path $RootDir "/artifacts/bin/linux/$($Arch)_$($Config)_$($Tls)/spinquic"
}

# Make sure the build is present.
if (!(Test-Path $SpinQuic)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

# Build up all the arguments to pass to the Powershell script.
$Arguments = "-Path $($SpinQuic) -Arguments 'both -timeout:$($Timeout) -repeat_count:$($RepeatCount)' -ShowOutput"
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
if ($CodeCoverage) {
    $Arguments += " -CodeCoverage"
}

# Run the script.
Invoke-Expression ($RunExecutable + " " + $Arguments)
