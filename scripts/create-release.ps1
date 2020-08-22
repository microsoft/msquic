<#

.SYNOPSIS
This script automates creating a new release branch from the latest main.

.PARAMETER Type
    Specifies the type of release (Major or Minor) and updates the current
    version accordingly.

.EXAMPLE
    create-release.ps1 -Type Major

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Major", "Minor")]
    [string]$Type
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Relevant file paths used by this script.
$RootDir = Split-Path $PSScriptRoot -Parent
$MsQuicVerFilePath = Join-Path $RootDir "src" "inc" "msquic.ver"
$UpdateVersionScript = Join-Path $RootDir "scripts" "update-version.ps1"

# Make sure we're on the latest main.
git checkout main
git pull

# Get the current major and minor version numbers from msquic.ver.
$Version = (Select-String -Path $MsQuicVerFilePath "VER_FILEVERSION *(.*),.*,0$" -AllMatches).Matches[0].Groups[1].Value.Replace(",", ".")

# Create a new release branch with the current version number.
git checkout -b "release/$Version"
git push --set-upstream origin "release/$Version"
Write-Host "New release branch created: release/$Versio"

# Go back to main and update the version number.
git checkout main
Invoke-Expression ($UpdateVersionScript + " -Part " + $Type)

# Create a new branch, commit the changes, push the branch and open the browser to create the PR.
git checkout -b "new-version-after-release-$Version"
git commit -am "Increment Version for $Type Release: $Version"
git push --set-upstream origin "new-version-after-release-$Version"
Start-Process https://github.com/microsoft/msquic/pull/new/new-version-after-release-$Version

Write-Host "Please continue the Pull Request process in the browser."
