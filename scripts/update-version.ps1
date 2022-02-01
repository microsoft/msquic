<#

.SYNOPSIS
This script automates updating all the necessary files for incrementing the
current version number.

.PARAMETER Part
    Specifies the part of the version number to increment:
    Major, Minor, or Patch

.EXAMPLE
    update-version.ps1 -Part Major

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Major", "Minor", "Patch")]
    [string]$Part
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Relevant file paths used by this script.
$RootDir = Split-Path $PSScriptRoot -Parent
$MsQuicVerFilePath = Join-Path $RootDir "src" "inc" "msquic.ver"
$CreateVPackFilePath = Join-Path $RootDir ".azure" "obtemplates" "create-vpack.yml"
$QnsFilePath = Join-Path $RootDir ".azure" "azure-pipelines.qns.yml"

# Get the current version number from the msquic.ver file.
$OriginalVersion = (Select-String -Path $MsQuicVerFilePath "VER_FILEVERSION *(.*),0$" -AllMatches).Matches[0].Groups[1].Value
$OriginalVersion2 = $OriginalVersion.Replace(",", ".")
$Version = $OriginalVersion.Split(",")
Write-Host "Current version: $Version"

# Increment the version number according to the input arg.
switch ($Part) {
    "Major"   { $Version[0] = [int]$Version[0] + 1; $Version[1] = 0; $Version[2] = 0 }
    "Minor"   { $Version[1] = [int]$Version[1] + 1; $Version[2] = 0  }
    "Patch"   { $Version[2] = [int]$Version[2] + 1 }
}
Write-Host "    New version: $Version"

# Write the new version to the files.
(Get-Content $MsQuicVerFilePath) `
    -replace "($OriginalVersion)", "$($Version[0]),$($Version[1]),$($Version[2])" `
    -replace "($OriginalVersion2)", "$($Version[0]).$($Version[1]).$($Version[2])" |`
    Out-File $MsQuicVerFilePath
(Get-Content $CreateVPackFilePath) `
    -replace "majorVer: (.*)", "majorVer: $($Version[0])" `
    -replace "minorVer: (.*)", "minorVer: $($Version[1])" `
    -replace "patchVer: (.*)", "patchVer: $($Version[2])" |`
    Out-File $CreateVPackFilePath
(Get-Content $QnsFilePath) `
    -replace "($OriginalVersion)", "$($Version[0]),$($Version[1]),$($Version[2])" `
    -replace "($OriginalVersion2)", "$($Version[0]).$($Version[1]).$($Version[2])" |`
    Out-File $QnsFilePath
