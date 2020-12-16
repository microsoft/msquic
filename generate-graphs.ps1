<#

.SYNOPSIS
This takes merged performance results and generates graphs to display. 
This is ran from merge-performance.ps1

#>

Using module .\mergetypes.psm1

param (
    [Parameter(Mandatory = $true)]
    [TestCommitModel]$Model,

    [Parameter(Mandatory = $true)]
    [string]$CommitFolder,

    [Parameter(Mandatory = $true)]
    [string]$BranchFolder
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Get-CommitHistory {
    [OutputType([CommitsFileModel[]])]
    param (
        [Parameter(Mandatory = $true)]
        [int]$DaysToReceive,

        [Parameter(Mandatory = $true)]
        [string]$BranchFolder
    )

    $CurrentDate = Get-Date
    $PastDate = $CurrentDate.AddDays(-$DaysToReceive)
    
    $CommitsFile = Join-Path $BranchFolder "commits.json"
    $CommitsContents = Get-Content $CommitsFile | ConvertFrom-Json | Where-Object -Property Date -GE $PastDate

    return $CommitsContents
}

function Get-CpuCommitData {
    [OutputType([TestCommitModel[]])]
    param (
        [Parameter(Mandatory = $true)]
        [CommitsFileModel[]]$CommitHistory,

        [Parameter(Mandatory = $true)]
        [string]$BranchFolder
    )

    $CpuData = @()

    foreach ($SingleCommitHis in $CommitHistory) {
        $CommitDataFile = Join-Path $BranchFolder $SingleCommitHis.CommitHash "cpu_data.json"
        $CpuData += Get-Content $CommitDataFile | ConvertFrom-Json
    }
    return $CpuData
}

class TestData {
    [string]$Platform;
    [double[]]$Results;
}

# Do Stuff Here
$CommitHistory = Get-CommitHistory -DaysToReceive 14 -BranchFolder $BranchFolder
$CpuCommitData = Get-CpuCommitData -CommitHistory $CommitHistory -BranchFolder $BranchFolder



#Write-Host $CpuCommitData
