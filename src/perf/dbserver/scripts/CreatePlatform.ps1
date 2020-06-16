<#

.SYNOPSIS
This script creates a new platform on the DB Server

.PARAMETER PlatformName
    The Platform name to create

.PARAMETER AuthKey
    The Authorization Key to use

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$PlatformName,

    [Parameter(Mandatory = $true)]
    [string]$AuthKey
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

class PlatformToCreate {
    [string]$PlatformName
    [string]$AuthKey
}

$ToPost = [PlatformToCreate]::new()
$ToPost.AuthKey = $AuthKey
$ToPost.PlatformName = $PlatformName

$JsonToPost = $ToPost | ConvertTo-Json

Invoke-RestMethod -Uri "https://msquicperformanceresults.azurewebsites.net/performance/createPlatform" -Body $JsonToPost -Method 'Post' -ContentType "application/json"
