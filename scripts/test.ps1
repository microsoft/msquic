<#

.SYNOPSIS
This script provides helpers for running executing the MsQuic tests.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.PARAMETER Filter
    A filter to include test cases from the list to execute. Multiple filters
    are separated by :. Negative filters are prefixed with -.

.PARAMETER ListTestCases
    Lists all the test cases.

.PARAMETER ExecutionMode
    Controls the execution mode when running each test case.

.PARAMETER IsolationMode
    Controls the isolation mode when running each test case.

.PARAMETER KeepOutputOnSuccess
    Don't discard console output or logs on success.

.PARAMETER GenerateXmlResults
    Generates an xml Test report for the run.

.PARAMETER Debugger
    Attaches the debugger to each test case run.

.PARAMETER InitialBreak
    Debugger starts broken into the process to allow setting breakpoints, etc.

.PARAMETER BreakOnFailure
    Triggers a break point on a test failure.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER CompressOutput
    Compresses the output files generated for failed test cases.

.PARAMETER NoProgress
    Disables the progress bar.

.Parameter EnableAppVerifier
    Enables all basic Application Verifier checks on test binaries.

.EXAMPLE
    test.ps1

.EXAMPLE
    test.ps1 -ListTestCases

.EXAMPLE
    test.ps1 -ListTestCases -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -LogProfile Full.Light

.EXAMPLE
    test.ps1 -LogProfile Full.Verbose -Compress

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
    [string]$Filter = "",

    [Parameter(Mandatory = $false)]
    [switch]$ListTestCases = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Serial", "Parallel")]
    [string]$ExecutionMode = "Serial",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Batch", "Isolated")]
    [string]$IsolationMode = "Batch",

    [Parameter(Mandatory = $false)]
    [switch]$KeepOutputOnSuccess = $false,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateXmlResults = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Debugger = $false,

    [Parameter(Mandatory = $false)]
    [switch]$InitialBreak = $false,

    [Parameter(Mandatory = $false)]
    [switch]$BreakOnFailure = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$CompressOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$NoProgress = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAppVerifier = $false
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

# Path to the run-gtest Powershell script.
$RunTest = Join-Path $RootDir "scripts/run-gtest.ps1"

# Path to the msquictest exectuable.
$MsQuicTest = $null
$MsQuicCoreTest = $null
$MsQuicPlatTest = $null
if ($IsWindows) {
    $MsQuicTest = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\msquictest.exe"
    $MsQuicCoreTest = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\msquiccoretest.exe"
    $MsQuicPlatTest = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\msquicplatformtest.exe"
} else {
    $MsQuicTest = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/msquictest"
    $MsQuicCoreTest = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/msquiccoretest"
    $MsQuicPlatTest = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/msquicplatformtest"
}

# Make sure the build is present.
if (!(Test-Path $MsQuicTest)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

# Build up all the arguments to pass to the Powershell script.
$TestArguments =  "-ExecutionMode $($ExecutionMode) -IsolationMode $($IsolationMode)"

if ("" -ne $Filter) {
    $TestArguments += " -Filter $($Filter)"
}
if ($ListTestCases) {
    $TestArguments += " -ListTestCases"
}
if ($KeepOutputOnSuccess) {
    $TestArguments += " -KeepOutputOnSuccess"
}
if ($GenerateXmlResults) {
    $TestArguments += " -GenerateXmlResults"
}
if ($Debugger) {
    $TestArguments += " -Debugger"
}
if ($InitialBreak) {
    $TestArguments += " -InitialBreak"
}
if ($BreakOnFailure) {
    $TestArguments += " -BreakOnFailure"
}
if ("None" -ne $LogProfile) {
    $TestArguments += " -LogProfile $($LogProfile) -ConvertLogs"
}
if ($CompressOutput) {
    $TestArguments += " -CompressOutput"
}
if ($NoProgress) {
    $TestArguments += " -NoProgress"
}
if ($EnableAppVerifier) {
    $TestArguments += " -EnableAppVerifier"
}

# Run the script.
Invoke-Expression ($RunTest + " -Path $($MsQuicCoreTest) " + $TestArguments)
Invoke-Expression ($RunTest + " -Path $($MsQuicPlatTest) " + $TestArguments)
Invoke-Expression ($RunTest + " -Path $($MsQuicTest) " + $TestArguments)
