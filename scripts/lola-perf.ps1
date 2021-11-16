<#

.SYNOPSIS
This script runs performance tests for LoLa and generates results in a table.

.PARAMETER Binary
    Specifies the build configuration to use.

#>


param (
    [Parameter(Mandatory = $true)]
    [string]$Binary,
    [Parameter(Mandatory = $false)]
    [string]$Server = "quic-server",
    [Parameter(Mandatory = $true)]
    [string]$Bind,
    [Parameter(Mandatory = $false)]
    [Int32[]]$ResponseSizes = @(512),
    [Parameter(Mandatory = $false)]
    [Int32]$NumIterations = 3
)

class TestResult {
    [string]$ResponseSize
    [Int32]$Min
    [Int32]$P50
    [Int32]$P90
    [Int32]$P99
    [Int32]$P999
    [Int32]$P9999
}

function RunTest (
    [string]$ResponseSize,
    [Int32]$NumIterations
    )
{
    $Result = [TestResult]::new()

    for ($i = 0; $i -lt $NumIterations; $i++) {
        $Output = Invoke-Expression  "$Binary -test:rps -target:$Server -bind:$Bind -conns:1 -requests:1 -request:512 -response:$ResponseSize"
        $MatchResults = $Output | Select-String -Pattern "Result: .*? RPS, Min: (.*?), Max: .*?, 50th: (.*?), 90th: (.*?), 99th: (.*?), 99.9th: (.*?), 99.99th: (.*?),"
        if (!$MatchResults) {
            Write-Error "Failed to parse secnetperf output"
        }

        $Result.ResponseSize = $ResponseSize
        $Result.Min += [Int32]$MatchResults.Matches.Groups[1].Value
        $Result.P50 += [Int32]$MatchResults.Matches.Groups[2].Value
        $Result.P90 += [Int32]$MatchResults.Matches.Groups[3].Value
        $Result.P99 += [Int32]$MatchResults.Matches.Groups[4].Value
        $Result.P999 += [Int32]$MatchResults.Matches.Groups[5].Value
        $Result.P9999 += [Int32]$MatchResults.Matches.Groups[6].Value
    }

    $Result.Min = $Result.Min / $NumIterations
    $Result.P50 = $Result.P50 / $NumIterations
    $Result.P90 = $Result.P90 / $NumIterations
    $Result.P99 = $Result.P99 / $NumIterations
    $Result.P999 = $Result.P999 / $NumIterations
    $Result.P9999 = $Result.P9999 / $NumIterations

    return $Result
}

[System.Collections.ArrayList]$Results = @()

foreach ($ResponseSize in $ResponseSizes) {
    $Result = RunTest $ResponseSize $NumIterations
    $_ = $Results.Add($Result)
}

$Results | Format-Table -AutoSize
