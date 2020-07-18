<#

.SYNOPSIS
This script merges the coverage data.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

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

$CoverageDir = Join-Path $RootDir "artifacts\coverage\windows\$($Arch)_$($Config)_$($Tls)"

$CoverageMergeParams = ""

if (Test-Path (Join-Path $CoverageDir "msquiccoretest.cov")) {
    $CoverageMergeParams += " --input_coverage $(Join-Path $CoverageDir "msquiccoretest.cov")"
}

if (Test-Path (Join-Path $CoverageDir "msquicplatformtest.cov")) {
    $CoverageMergeParams += " --input_coverage $(Join-Path $CoverageDir "msquicplatformtest.cov")"
}

if (Test-Path (Join-Path $CoverageDir "msquictest.cov")) {
    $CoverageMergeParams += " --input_coverage $(Join-Path $CoverageDir "msquictest.cov")"
}

if (Test-Path (Join-Path $CoverageDir "spinquic.cov")) {
    $CoverageMergeParams += " --input_coverage $(Join-Path $CoverageDir "spinquic.cov")"
}

if ($CoverageMergeParams -ne "") {
    $CoverageMergeParams +=  " --export_type cobertura:$(Join-Path $CoverageDir "msquiccoverage.xml")"

    $CoverageExe = 'C:\"Program Files"\OpenCppCoverage\OpenCppCoverage.exe'
    Invoke-Expression ($CoverageExe + $CoverageMergeParams) | Out-Null
} else {
    Write-Warning "No coverage results to merge!"
}
