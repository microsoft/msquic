<#

.SYNOPSIS
This synchronizes a branch on the current repository to the mirror repo.

.EXAMPLE
    sync-mirror.ps1

.EXAMPLE
    sync-mirror.ps1 -Branch release/xxxx

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$Branch = "master"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Make sure we're in the correct branch.
git checkout $Branch

# Add the AzDO repo as a remote.
git remote add azdo-mirror "https://nibanks:$Env:AzDO_PAT@mscodehub.visualstudio.com/msquic/_git/msquic"

# Reset branch to origin.
git reset --hard origin/$Branch

# Push to the AzDO repo.
git push azdo-mirror $Branch
