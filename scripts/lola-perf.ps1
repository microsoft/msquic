<#

.SYNOPSIS
This script runs performance tests for LoLa using secnetperf and generates results in a table.

.PARAMETER SecNetPerfBinary
    Specifies the secnetperf binary to use.

.PARAMETER Target
    Specifies -target parameter for secnetperf.

.PARAMETER Bind
    Specifies -bind parameter for secnetperf.

.PARAMETER Responses
    Specifies -response parameter for secnetperf.

.PARAMETER NumIterations
    Specifies the number of iterations to be run.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$SecNetPerfBinary,
    [Parameter(Mandatory = $false)]
    [string]$Target = "quic-server",
    [Parameter(Mandatory = $false)]
    [string]$Bind = "0.0.0.0",
    [Parameter(Mandatory = $false)]
    [Int32[]]$Responses = @(512, 1024, 4096, 8192, 16384, 32768, 65536),
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

[Int32]$script:TotalNumTestCases = 0
[Int32]$script:NumTestCasesCompleted = 0

function RunTest (
    [string]$ResponseSize,
    [Int32]$NumIterations
    )
{
    $Result = [TestResult]::new()
    $Result.ResponseSize = $ResponseSize

    [System.Collections.ArrayList]$Min = @()
    [System.Collections.ArrayList]$P50 = @();
    [System.Collections.ArrayList]$P90 = @();
    [System.Collections.ArrayList]$P99 = @();
    [System.Collections.ArrayList]$P999 = @();
    [System.Collections.ArrayList]$P9999 = @();

    for ($i = 0; $i -lt $NumIterations; $i++) {
        $Output = Invoke-Expression  "$SecNetPerfBinary -test:rps -target:$Target -bind:$Bind -conns:1 -requests:1 -request:512 -response:$ResponseSize"
        $MatchResults = $Output | Select-String -Pattern "Result: .*? RPS, Min: (.*?), Max: .*?, 50th: (.*?), 90th: (.*?), 99th: (.*?), 99.9th: (.*?), 99.99th: (.*?),"
        if (!$MatchResults) {
            Write-Error "Failed to parse secnetperf output"
        }

        $Groups = $MatchResults.Matches.Groups

        Write-Debug "$ResponseSize,$([Int32]$Groups[1].Value),$([Int32]$Groups[2].Value),$([Int32]$Groups[3].Value),$([Int32]$Groups[4].Value),$([Int32]$Groups[5].Value),$([Int32]$Groups[6].Value)"

        $_ = $Min.Add([Int32]$Groups[1].Value)
        $_ = $P50.Add([Int32]$Groups[2].Value)
        $_ = $P90.Add([Int32]$Groups[3].Value)
        $_ = $P99.Add([Int32]$Groups[4].Value)
        $_ = $P999.Add([Int32]$Groups[5].Value)
        $_ = $P9999.Add([Int32]$Groups[6].Value)

        $script:NumTestCasesCompleted += 1
        Write-Progress -Activity "Running tests" -Status "Progress:" -PercentComplete (($script:NumTestCasesCompleted / $script:TotalNumTestCases) * 100)
    }

    $Result.Min = ($Min | Sort-Object)[$Min.Count / 2]
    $Result.P50 = ($P50 | Sort-Object)[$Min.Count / 2]
    $Result.P90 = ($P90 | Sort-Object)[$Min.Count / 2]
    $Result.P99 = ($P99 | Sort-Object)[$Min.Count / 2]
    $Result.P999 = ($P999 | Sort-Object)[$Min.Count / 2]
    $Result.P9999 = ($P9999 | Sort-Object)[$Min.Count / 2]

    return $Result
}

[System.Collections.ArrayList]$Results = @()

$script:TotalNumTestCases = $Responses.Count * $NumIterations

Write-Debug "ResponseSize,Min,P50,P90,P99,P999,P9999"

foreach ($Response in $Responses) {
    $Result = RunTest $Response $NumIterations
    $_ = $Results.Add($Result)
}

$Results | Format-Table -AutoSize
