<#

.SYNOPSIS
This script runs the MsQuic tests.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.PARAMETER ExtraArtifactDir
    Add an extra classifier to the artifact directory to allow publishing alternate builds of same base library

.PARAMETER Kernel
    Runs the Windows kernel mode tests.

.PARAMETER Filter
    A filter to include test cases from the list to execute. Multiple filters
    are separated by :. Negative filters are prefixed with -.

.PARAMETER ListTestCases
    Lists all the test cases.

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

.Parameter CodeCoverage
    Collect code coverage for this test run. Incompatible with -Kernel and -Debugger.

.Parameter AZP
    Runs in Azure Pipelines mode.

.Parameter ErrorsAsWarnings
    Treats all errors as warnings.

.Parameter DuoNic
    Uses DuoNic instead of loopback (DuoNic must already be installed via 'prepare-machine.ps1 -InstallDuoNic').

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
    [string]$Arch = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$Kernel = $false,

    [Parameter(Mandatory = $false)]
    [string]$Filter = "",

    [Parameter(Mandatory = $false)]
    [switch]$ListTestCases = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Batch", "Isolated")]
    [string]$IsolationMode = "Isolated",

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
    [switch]$EnableAppVerifier = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableTcpipVerifier = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage = $false,

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$AZP = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SkipUnitTests = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ErrorsAsWarnings = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DuoNic = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Test-Administrator
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ($IsWindows -and !(Test-Administrator)) {
    Write-Warning "We recommend running this test as administrator. Crash dumps will not work"
}

# Validate the the kernel switch.
if ($Kernel -and !$IsWindows) {
    Write-Error "-Kernel switch only supported on Windows";
}

# Validate the code coverage switch.
if ($CodeCoverage) {
    if (!$IsWindows) {
        Write-Error "-CodeCoverage switch only supported on Windows";
    }
    if ($Kernel) {
        Write-Error "-CodeCoverage is not supported for kernel mode tests";
    }
    if ($Debugger) {
        Write-Error "-CodeCoverage switch is not supported with debugging";
    }
    if (!(Test-Path "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe")) {
        Write-Error "Code coverage tools are not installed";
    }
}

$BuildConfig = & (Join-Path $PSScriptRoot get-buildconfig.ps1) -Tls $Tls -Arch $Arch -ExtraArtifactDir $ExtraArtifactDir -Config $Config

$Tls = $BuildConfig.Tls
$Arch = $BuildConfig.Arch
$RootArtifactDir = $BuildConfig.ArtifactsDir

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Coverage destination directory.
$CoverageDir = Join-Path $RootDir "artifacts" "coverage"

if ($CodeCoverage) {
    # Clear old coverage data
    if (Test-Path $CoverageDir) {
        Remove-Item -Path (Join-Path $CoverageDir '*.cov') -Force
    }
}

# Path to the run-gtest Powershell script.
$RunTest = Join-Path $RootDir "scripts/run-gtest.ps1"

if ("" -ne $ExtraArtifactDir -and $Kernel) {
    Write-Error "Kernel not supported with extra artifact dir"
}

# Path to the msquictest executable.
$MsQuicTest = $null
$MsQuicCoreTest = $null
$MsQuicPlatTest = $null
$KernelPath = $null;
if ($IsWindows) {
    $MsQuicTest = Join-Path $RootArtifactDir  "msquictest.exe"
    $MsQuicCoreTest = Join-Path $RootArtifactDir "msquiccoretest.exe"
    $MsQuicPlatTest = Join-Path $RootArtifactDir "msquicplatformtest.exe"
    $KernelPath = Join-Path $RootDir "\artifacts\bin\winkernel\$($Arch)_$($Config)_$($Tls)"
}  elseif ($IsLinux -or $IsMacOS) {
    $MsQuicTest = Join-Path $RootArtifactDir "msquictest"
    $MsQuicCoreTest = Join-Path $RootArtifactDir "msquiccoretest"
    $MsQuicPlatTest = Join-Path $RootArtifactDir "msquicplatformtest"
} else {
    Write-Error "Unsupported platform type!"
}

# Make sure the build is present.
if (!(Test-Path $MsQuicTest)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}
if ($Kernel) {
    if (!(Test-Path (Join-Path $KernelPath "msquictestpriv.sys"))) {
        Write-Error "Kernel binaries do not exist!"
    }
}

$PfxFile = Join-Path $RootArtifactDir "selfsignedservercert.pfx"
if (!(Test-Path $PfxFile)) {
    $MyPath = Split-Path -Path $PSCommandPath -Parent
    $ScriptPath = Join-Path $MyPath install-test-certificates.ps1

    &$ScriptPath -OutputFile $PfxFile
}

# Build up all the arguments to pass to the Powershell script.
$TestArguments =  "-IsolationMode $IsolationMode -PfxPath $PfxFile"

if ($DuoNic) {
    $TestArguments += " -DuoNic"
}
if ($Kernel) {
    $TestArguments += " -Kernel $KernelPath"
}
if ("" -ne $Filter) {
    $TestArguments += " -Filter $Filter"
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
    $TestArguments += " -LogProfile $LogProfile"
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
if ($EnableTcpipVerifier) {
    $TestArguments += " -EnableTcpipVerifier"
}
if ($CodeCoverage) {
    $TestArguments += " -CodeCoverage"
}
if ($AZP) {
    $TestArguments += " -AZP"
}
if ($ErrorsAsWarnings) {
    $TestArguments += " -ErrorsAsWarnings"
}

if (![string]::IsNullOrWhiteSpace($ExtraArtifactDir)) {
    $TestArguments += " -ExtraArtifactDir $ExtraArtifactDir"
}

# Run the script.
if (!$Kernel -and !$SkipUnitTests) {
    Invoke-Expression ($RunTest + " -Path $MsQuicCoreTest " + $TestArguments)
    Invoke-Expression ($RunTest + " -Path $MsQuicPlatTest " + $TestArguments)
}
Invoke-Expression ($RunTest + " -Path $MsQuicTest " + $TestArguments)

if ($CodeCoverage) {
    # Merge code coverage results
    $CoverageMergeParams = ""

    foreach ($file in $(Get-ChildItem -Path $CoverageDir -Filter '*.cov')) {
        $CoverageMergeParams += " --input_coverage $(Join-Path $CoverageDir $file.Name)"
    }

    if ($CoverageMergeParams -ne "") {
        $CoverageMergeParams +=  " --export_type cobertura:$(Join-Path $CoverageDir "msquiccoverage.xml")"

        $CoverageExe = 'C:\"Program Files"\OpenCppCoverage\OpenCppCoverage.exe'
        Invoke-Expression ($CoverageExe + $CoverageMergeParams) | Out-Null
    } else {
        Write-Warning "No coverage results to merge!"
    }
}
