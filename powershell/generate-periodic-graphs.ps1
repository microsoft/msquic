<#

.SYNOPSIS
This takes merged performance results and generates graphs to display.
This is ran from merge-performance.ps1

#>

Using module .\mergetypes.psm1

param (
    [Parameter(Mandatory = $true)]
    [string]$BranchName
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Get-LatestCommit {
    [OutputType([CommitsFileModel[]])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$BranchFolder
    )

    $CommitsFile = Join-Path $BranchFolder "commits.json"
    $CommitsContents = Get-Content $CommitsFile | ConvertFrom-Json | Select-Object -First 1

    return $CommitsContents[0]
}



function Get-RpsResultsPerResponseSizeConnCountJs {
    param (
        [Parameter(Mandatory = $true)]
        [TestCommitModel[]]$RpsData,

        [Parameter(Mandatory = $true)]
        [int]$RequestSize,
        [Parameter(Mandatory = $true)]
        [int]$ParallelRequests
    )

    # X Axis Conn Count, Y Axis RPS, Legend ResponseSize
    # Fix request size at 0, Parallel Conns at 30

    $TestList = [System.Collections.Generic.SortedDictionary[int, [System.Collections.Generic.List[TestModel]]]]::new()

    foreach ($Test in $RpsData.Tests) {
        if ($null -eq $Test.RpsConfig) {
            continue;
        }
        if ($Test.RpsConfig.RequestSize -eq $RequestSize -and $Test.RpsConfig.ParallelRequests -eq $ParallelRequests) {
            if ($TestList.ContainsKey($Test.RpsConfig.ResponseSize)) {
                $TestList[$Test.RpsConfig.ResponseSize].Add($Test)
            } else {
                $List = [System.Collections.Generic.List[TestModel]]::new();
                $List.Add($Test)
                $TestList.Add($Test.RpsConfig.ResponseSize, $List)
            }
        }
    }

    $OutputData = "{LegendName: `"Response Size`", XName: `"Connection Count`", FixedVariables: [{name: `"Request Size`", value: `"$RequestSize`"}, {name: `"Parallel Requests`", value: `"$ParallelRequests`"}], Data: ["
    # Generate scatter data
    foreach ($Test in $TestList.GetEnumerator()) {
        # Sort Data
        $Test.Value.Sort({ $args[0].RpsConfig.ConnectionCount - $args[1].RpsConfig.ConnectionCount })

        $Data = "{LegendValue: `"$($Test.Key) Bytes`", DataPairs: ["
        foreach ($Result in $Test.Value) {
            $Average = ($Result.Results  | Measure-Object -Average).Average
            $Data += "{x: $($Result.RpsConfig.ConnectionCount), y: $Average},"
        }
        $Data += "]},"
        $OutputData += $Data
    }
    $OutputData += "]}"
    return $OutputData
}

$RootDir = Split-Path $PSScriptRoot -Parent
$BranchFolder = Join-Path $RootDir 'periodic' $BranchName
$LatestCommit = Get-LatestCommit -BranchFolder $BranchFolder
$RunFolder = Join-Path $BranchFolder $LatestCommit.Date

$RpsData = Get-Content (Join-Path $RunFolder "rps_data.json") | ConvertFrom-Json

$LatencyFolder = Join-Path $BranchFolder $LatestCommit.CommitHash "RpsLatency"

$RpsResultResponseConn = Get-RpsResultsPerResponseSizeConnCountJs -RpsData $RpsData -RequestSize 0 -ParallelRequests 30

$JsOutput = "[$RpsResultResponseConn];"

$TemplateFolder = Join-Path $RootDir "assets" "periodicrun"
$DataFileIn = Join-Path $TemplateFolder "data.js.in"
$DataFileContents = Get-Content $DataFileIn

$DataFileContents = $DataFileContents.Replace("PERIODIC_RPS_GRAPHS", $JsOutput);
$DataFileContents = $DataFileContents.Replace("COMMIT_HASH", "`"$($LatestCommit.CommitHash)`";");
$DataFileContents = $DataFileContents.Replace("RUN_DATE", "new Date($($LatestCommit.Date));");

$OutputFolder = $RunFolder
New-Item -Path $OutputFolder -ItemType "directory" -Force | Out-Null
$DataFileOut = Join-Path $OutputFolder "data.js"
$DataFileContents | Set-Content $DataFileOut

# Take template folder, and copy to commit
Copy-Item -Path $TemplateFolder/* -Destination $OutputFolder -Exclude "data.js.in" -Force