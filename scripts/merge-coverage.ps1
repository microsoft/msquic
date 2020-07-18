<#

.SYNOPSIS
This script merges the coverage data.

#>

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$CoverageDir = Join-Path $RootDir "artifacts" "coverage"

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