<#

.SYNOPSIS
This script merges the coverage data.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.PARAMETER Local
    Indicates local execution/usage (not Azure Pipelines) of the script.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "openssl3")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$Local = $false
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

# Path to the coverage tool.
$CoverageExe = 'C:\"Program Files"\OpenCppCoverage\OpenCppCoverage.exe'

# The input directory to search for files. When run locally (not on Azure Pipelines)
# the files are in a different location.
$CoverageDir = Join-Path $RootDir "artifacts\coverage\windows\$($Arch)_$($Config)_$($Tls)"
if ($Local) {
    $CoverageDir = Join-Path $RootDir "artifacts\coverage"
}

# Build up the args with the list of input files.
$CoverageMergeParams = ""
foreach ($file in $(Get-ChildItem -Path $CoverageDir -Filter '*.cov')) {
    $CoverageMergeParams += " --input_coverage $(Join-Path $CoverageDir $file.Name)"
}
if ($CoverageMergeParams -eq "") {
    Write-Error "No coverage results to merge!"
}

if ($Local) {
    # Locally, output the HTML report.
    $CoverageMergeParams +=  " --export_type html:$(Join-Path $CoverageDir "report")"
} else {
    # Use cobertura format for Azure Pipelines.
    $CoverageMergeParams +=  " --export_type cobertura:$(Join-Path $CoverageDir "msquiccoverage.xml")"
}

# Call the tool to merge the files into the appropriate format.
Invoke-Expression ($CoverageExe + $CoverageMergeParams) | Out-Null

if ($Local) {
    # Open up the HTML report that was just generated.
    start (Join-Path $CoverageDir "report\index.html")
}
