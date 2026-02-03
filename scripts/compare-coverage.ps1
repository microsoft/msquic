<#

.SYNOPSIS
    Compares two Cobertura XML coverage reports and generates a comparison summary.

.PARAMETER BaselineCoverage
    Path to the baseline (pre-PR) Cobertura XML coverage report.

.PARAMETER CurrentCoverage
    Path to the current (post-PR) Cobertura XML coverage report.

.PARAMETER OutputPath
    Path to write the comparison report (JSON format).

.PARAMETER ChangedFiles
    Optional JSON array of changed file paths to focus comparison on.

.EXAMPLE
    compare-coverage.ps1 -BaselineCoverage baseline.xml -CurrentCoverage current.xml -OutputPath comparison.json

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$BaselineCoverage,

    [Parameter(Mandatory = $true)]
    [string]$CurrentCoverage,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "coverage-comparison.json",

    [Parameter(Mandatory = $false)]
    [string]$ChangedFiles = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Parse-CoberturaCoverage {
    param (
        [string]$XmlPath
    )

    if (-not (Test-Path $XmlPath)) {
        Write-Warning "Coverage file not found: $XmlPath"
        return @{
            LineCoverage = 0
            BranchCoverage = 0
            LinesCovered = 0
            LinesValid = 0
            BranchesCovered = 0
            BranchesValid = 0
            Packages = @{}
            Files = @{}
            NotFound = $true
        }
    }

    [xml]$xml = Get-Content $XmlPath
    $coverage = $xml.coverage

    $result = @{
        LineCoverage = [double]($coverage.'line-rate' ?? 0) * 100
        BranchCoverage = [double]($coverage.'branch-rate' ?? 0) * 100
        LinesCovered = [int]($coverage.'lines-covered' ?? 0)
        LinesValid = [int]($coverage.'lines-valid' ?? 0)
        BranchesCovered = [int]($coverage.'branches-covered' ?? 0)
        BranchesValid = [int]($coverage.'branches-valid' ?? 0)
        Packages = @{}
        Files = @{}
        NotFound = $false
    }

    # Parse package-level and file-level coverage
    foreach ($package in $coverage.packages.package) {
        $packageName = $package.name
        $result.Packages[$packageName] = @{
            LineCoverage = [double]($package.'line-rate' ?? 0) * 100
            BranchCoverage = [double]($package.'branch-rate' ?? 0) * 100
        }

        foreach ($class in $package.classes.class) {
            $filename = $class.filename
            if ($filename) {
                # Normalize path separators
                $filename = $filename -replace '\\', '/'
                
                $linesCovered = 0
                $linesTotal = 0
                $branchesCovered = 0
                $branchesTotal = 0

                foreach ($line in $class.lines.line) {
                    $linesTotal++
                    if ([int]$line.hits -gt 0) {
                        $linesCovered++
                    }
                    
                    if ($line.'condition-coverage') {
                        $match = [regex]::Match($line.'condition-coverage', '\((\d+)/(\d+)\)')
                        if ($match.Success) {
                            $branchesCovered += [int]$match.Groups[1].Value
                            $branchesTotal += [int]$match.Groups[2].Value
                        }
                    }
                }

                if (-not $result.Files.ContainsKey($filename)) {
                    $result.Files[$filename] = @{
                        LinesCovered = $linesCovered
                        LinesTotal = $linesTotal
                        BranchesCovered = $branchesCovered
                        BranchesTotal = $branchesTotal
                        LineCoverage = if ($linesTotal -gt 0) { ($linesCovered / $linesTotal) * 100 } else { 0 }
                        BranchCoverage = if ($branchesTotal -gt 0) { ($branchesCovered / $branchesTotal) * 100 } else { 0 }
                    }
                } else {
                    # Aggregate if file appears multiple times
                    $result.Files[$filename].LinesCovered += $linesCovered
                    $result.Files[$filename].LinesTotal += $linesTotal
                    $result.Files[$filename].BranchesCovered += $branchesCovered
                    $result.Files[$filename].BranchesTotal += $branchesTotal
                    
                    $total = $result.Files[$filename].LinesTotal
                    $covered = $result.Files[$filename].LinesCovered
                    $result.Files[$filename].LineCoverage = if ($total -gt 0) { ($covered / $total) * 100 } else { 0 }
                    
                    $bTotal = $result.Files[$filename].BranchesTotal
                    $bCovered = $result.Files[$filename].BranchesCovered
                    $result.Files[$filename].BranchCoverage = if ($bTotal -gt 0) { ($bCovered / $bTotal) * 100 } else { 0 }
                }
            }
        }
    }

    return $result
}

function Compare-Coverage {
    param (
        [hashtable]$Baseline,
        [hashtable]$Current,
        [array]$ChangedFilesList
    )

    $comparison = @{
        Summary = @{
            Baseline = @{
                LineCoverage = [math]::Round($Baseline.LineCoverage, 2)
                BranchCoverage = [math]::Round($Baseline.BranchCoverage, 2)
                LinesCovered = $Baseline.LinesCovered
                LinesValid = $Baseline.LinesValid
                NotFound = $Baseline.NotFound
            }
            Current = @{
                LineCoverage = [math]::Round($Current.LineCoverage, 2)
                BranchCoverage = [math]::Round($Current.BranchCoverage, 2)
                LinesCovered = $Current.LinesCovered
                LinesValid = $Current.LinesValid
                NotFound = $Current.NotFound
            }
            Delta = @{
                LineCoverage = [math]::Round($Current.LineCoverage - $Baseline.LineCoverage, 2)
                BranchCoverage = [math]::Round($Current.BranchCoverage - $Baseline.BranchCoverage, 2)
                LinesCovered = $Current.LinesCovered - $Baseline.LinesCovered
                LinesValid = $Current.LinesValid - $Baseline.LinesValid
            }
        }
        ChangedFiles = @()
        NewFiles = @()
        RemovedFiles = @()
        ImprovedFiles = @()
        RegressedFiles = @()
    }

    # Compare changed files specifically
    if ($ChangedFilesList -and $ChangedFilesList.Count -gt 0) {
        foreach ($file in $ChangedFilesList) {
            $normalizedFile = $file -replace '\\', '/'
            
            $baselineFile = $null
            $currentFile = $null
            
            # Try to find matching file in coverage data
            foreach ($key in $Baseline.Files.Keys) {
                if ($key -like "*$normalizedFile" -or $normalizedFile -like "*$key") {
                    $baselineFile = $Baseline.Files[$key]
                    break
                }
            }
            
            foreach ($key in $Current.Files.Keys) {
                if ($key -like "*$normalizedFile" -or $normalizedFile -like "*$key") {
                    $currentFile = $Current.Files[$key]
                    break
                }
            }

            $fileComparison = @{
                File = $file
                Baseline = if ($baselineFile) { 
                    @{
                        LineCoverage = [math]::Round($baselineFile.LineCoverage, 2)
                        BranchCoverage = [math]::Round($baselineFile.BranchCoverage, 2)
                        LinesCovered = $baselineFile.LinesCovered
                        LinesTotal = $baselineFile.LinesTotal
                    }
                } else { $null }
                Current = if ($currentFile) {
                    @{
                        LineCoverage = [math]::Round($currentFile.LineCoverage, 2)
                        BranchCoverage = [math]::Round($currentFile.BranchCoverage, 2)
                        LinesCovered = $currentFile.LinesCovered
                        LinesTotal = $currentFile.LinesTotal
                    }
                } else { $null }
            }

            if ($baselineFile -and $currentFile) {
                $fileComparison.Delta = @{
                    LineCoverage = [math]::Round($currentFile.LineCoverage - $baselineFile.LineCoverage, 2)
                    BranchCoverage = [math]::Round($currentFile.BranchCoverage - $baselineFile.BranchCoverage, 2)
                }
                $comparison.ChangedFiles += $fileComparison

                if ($fileComparison.Delta.LineCoverage -gt 0) {
                    $comparison.ImprovedFiles += $fileComparison
                } elseif ($fileComparison.Delta.LineCoverage -lt 0) {
                    $comparison.RegressedFiles += $fileComparison
                }
            } elseif ($currentFile -and -not $baselineFile) {
                $comparison.NewFiles += $fileComparison
            } elseif ($baselineFile -and -not $currentFile) {
                $comparison.RemovedFiles += $fileComparison
            }
        }
    }

    return $comparison
}

function Format-CoverageReport {
    param (
        [hashtable]$Comparison
    )

    $sb = [System.Text.StringBuilder]::new()

    # Check if baseline or current coverage is missing
    $baselineNotFound = $Comparison.Summary.Baseline.NotFound
    $currentNotFound = $Comparison.Summary.Current.NotFound

    # Overall summary
    [void]$sb.AppendLine("## 📊 Code Coverage Comparison")
    [void]$sb.AppendLine("")

    # Show warning if baseline is missing
    if ($baselineNotFound) {
        [void]$sb.AppendLine("> ⚠️ **Baseline coverage not available** - No tests were run on the pre-PR version, or coverage file was not generated.")
        [void]$sb.AppendLine("> Showing current PR coverage only. Delta comparison is not available.")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| Metric | Current (Post-PR) |")
        [void]$sb.AppendLine("|--------|-------------------|")
        [void]$sb.AppendLine("| Line Coverage | $($Comparison.Summary.Current.LineCoverage)% |")
        [void]$sb.AppendLine("| Branch Coverage | $($Comparison.Summary.Current.BranchCoverage)% |")
        [void]$sb.AppendLine("| Lines Covered | $($Comparison.Summary.Current.LinesCovered) |")
        [void]$sb.AppendLine("| Total Lines | $($Comparison.Summary.Current.LinesValid) |")
    } elseif ($currentNotFound) {
        [void]$sb.AppendLine("> ⚠️ **Current coverage not available** - No tests were run on the post-PR version, or coverage file was not generated.")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| Metric | Baseline (Pre-PR) |")
        [void]$sb.AppendLine("|--------|-------------------|")
        [void]$sb.AppendLine("| Line Coverage | $($Comparison.Summary.Baseline.LineCoverage)% |")
        [void]$sb.AppendLine("| Branch Coverage | $($Comparison.Summary.Baseline.BranchCoverage)% |")
        [void]$sb.AppendLine("| Lines Covered | $($Comparison.Summary.Baseline.LinesCovered) |")
        [void]$sb.AppendLine("| Total Lines | $($Comparison.Summary.Baseline.LinesValid) |")
    } else {
        [void]$sb.AppendLine("| Metric | Baseline | Current | Delta |")
        [void]$sb.AppendLine("|--------|----------|---------|-------|")

        $lineDelta = $Comparison.Summary.Delta.LineCoverage
        $lineIcon = if ($lineDelta -gt 0) { "🟢 +" } elseif ($lineDelta -lt 0) { "🔴 " } else { "⚪ " }
        [void]$sb.AppendLine("| Line Coverage | $($Comparison.Summary.Baseline.LineCoverage)% | $($Comparison.Summary.Current.LineCoverage)% | $lineIcon$($lineDelta)% |")

        $branchDelta = $Comparison.Summary.Delta.BranchCoverage
        $branchIcon = if ($branchDelta -gt 0) { "🟢 +" } elseif ($branchDelta -lt 0) { "🔴 " } else { "⚪ " }
        [void]$sb.AppendLine("| Branch Coverage | $($Comparison.Summary.Baseline.BranchCoverage)% | $($Comparison.Summary.Current.BranchCoverage)% | $branchIcon$($branchDelta)% |")

        [void]$sb.AppendLine("| Lines Covered | $($Comparison.Summary.Baseline.LinesCovered) | $($Comparison.Summary.Current.LinesCovered) | $($Comparison.Summary.Delta.LinesCovered) |")
        [void]$sb.AppendLine("| Total Lines | $($Comparison.Summary.Baseline.LinesValid) | $($Comparison.Summary.Current.LinesValid) | $($Comparison.Summary.Delta.LinesValid) |")
    }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("")

    # Only show changed files sections if we have both baseline and current
    if (-not $baselineNotFound -and -not $currentNotFound) {
        # Changed files coverage
        if ($Comparison.ChangedFiles.Count -gt 0) {
            [void]$sb.AppendLine("### 📁 Coverage for Changed Files")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("<details>")
            [void]$sb.AppendLine("<summary>Click to expand ($($Comparison.ChangedFiles.Count) files)</summary>")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("| File | Baseline | Current | Delta |")
            [void]$sb.AppendLine("|------|----------|---------|-------|")

            foreach ($file in $Comparison.ChangedFiles) {
                $delta = $file.Delta.LineCoverage
                $icon = if ($delta -gt 0) { "🟢 +" } elseif ($delta -lt 0) { "🔴 " } else { "⚪ " }
                $shortName = Split-Path $file.File -Leaf
                [void]$sb.AppendLine("| ``$shortName`` | $($file.Baseline.LineCoverage)% | $($file.Current.LineCoverage)% | $icon$($delta)% |")
            }

            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("</details>")
            [void]$sb.AppendLine("")
        }

        # Regressed files warning
        if ($Comparison.RegressedFiles.Count -gt 0) {
            [void]$sb.AppendLine("### ⚠️ Files with Decreased Coverage")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("| File | Baseline | Current | Delta |")
            [void]$sb.AppendLine("|------|----------|---------|-------|")

            foreach ($file in $Comparison.RegressedFiles) {
                $shortName = Split-Path $file.File -Leaf
                [void]$sb.AppendLine("| ``$shortName`` | $($file.Baseline.LineCoverage)% | $($file.Current.LineCoverage)% | 🔴 $($file.Delta.LineCoverage)% |")
            }
            [void]$sb.AppendLine("")
        }
    }

    # New files (show even if baseline is missing, since these are new in current)
    if ($Comparison.NewFiles.Count -gt 0) {
        [void]$sb.AppendLine("### 🆕 New Files")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| File | Coverage |")
        [void]$sb.AppendLine("|------|----------|")

        foreach ($file in $Comparison.NewFiles) {
            $shortName = Split-Path $file.File -Leaf
            [void]$sb.AppendLine("| ``$shortName`` | $($file.Current.LineCoverage)% |")
        }
        [void]$sb.AppendLine("")
    }

    return $sb.ToString()
}

# Main execution
Write-Host "Parsing baseline coverage: $BaselineCoverage"
$baseline = Parse-CoberturaCoverage -XmlPath $BaselineCoverage

Write-Host "Parsing current coverage: $CurrentCoverage"
$current = Parse-CoberturaCoverage -XmlPath $CurrentCoverage

# Parse changed files if provided
$changedFilesList = @()
if ($ChangedFiles -and $ChangedFiles -ne "") {
    try {
        $changedFilesList = $ChangedFiles | ConvertFrom-Json
    } catch {
        Write-Warning "Failed to parse changed files JSON: $_"
    }
}

Write-Host "Comparing coverage reports..."
$comparison = Compare-Coverage -Baseline $baseline -Current $current -ChangedFilesList $changedFilesList

# Generate markdown report
$markdownReport = Format-CoverageReport -Comparison $comparison
$comparison.MarkdownReport = $markdownReport

# Output results
$comparison | ConvertTo-Json -Depth 10 | Set-Content $OutputPath
Write-Host "Coverage comparison written to: $OutputPath"

# Also output summary to console
Write-Host ""
Write-Host "=== Coverage Summary ==="
Write-Host "Baseline Line Coverage: $($comparison.Summary.Baseline.LineCoverage)%"
Write-Host "Current Line Coverage: $($comparison.Summary.Current.LineCoverage)%"
Write-Host "Delta: $($comparison.Summary.Delta.LineCoverage)%"
Write-Host ""

# Return the markdown report for use in CI
return $markdownReport
