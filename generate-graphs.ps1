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

# Do Stuff Here

