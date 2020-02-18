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

# Verify the PAT environmental variable is set.
if ($null -eq $Env:AzDO_PAT -or "" -eq $Env:AzDO_PAT) {
    Write-Error "PAT for Azure DevOps Repo doesn't exist!"
}

# Make sure we're in the correct branch.
git checkout $Branch

# Add the AzDO repo as a remote.
git remote add azdo-mirror "https://nibanks:$Env:AzDO_PAT@mscodehub.visualstudio.com/msquic/_git/msquic"

# Reset branch to origin.
git reset --hard origin/$Branch

# Push to the AzDO repo.
try {
    git push azdo-mirror $Branch
} catch {
    Write-Host "Supressing exception while running 'git push'"
}

Write-Host "Successfully mirrored latest changes"
