<#

.SYNOPSIS
This script creates a new test on the DB Server

.PARAMETER PlatformName
    The Platform name to add the test to

.PARAMETER TestName
    The Test name to add

.PARAMETER AuthKey
    The Authorization Key to use

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$PlatformName,

    [Parameter(Mandatory = $true)]
    [string]$TestName,

    [Parameter(Mandatory = $true)]
    [string]$AuthKey
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

class TestToCreate {
    [string]$PlatformName
    [string]$TestName
    [string]$AuthKey
}

$ToPost = [TestToCreate]::new()
$ToPost.AuthKey = $AuthKey
$ToPost.PlatformName = $PlatformName
$ToPost.TestName = $TestName

$JsonToPost = $ToPost | ConvertTo-Json

Invoke-RestMethod -Uri "https://msquicperformanceresults.azurewebsites.net/performance/createTest" -Body $JsonToPost -Method 'Post' -ContentType "application/json"
