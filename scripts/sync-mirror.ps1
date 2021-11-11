<#

.SYNOPSIS
This synchronizes a branch or tag on the current repository to the mirror repo.

.EXAMPLE
    sync-mirror.ps1

.EXAMPLE
    sync-mirror.ps1 -Source refs/heads/release/1.0.0

.EXAMPLE
    sync-mirror.ps1 -Source refs/tags/v1.0.0

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$Source = "refs/heads/main"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Verify the PAT environmental variable is set.
if ($null -eq $Env:AzDO_PAT -or "" -eq $Env:AzDO_PAT) {
    Write-Error "PAT for Azure DevOps Repo doesn't exist!"
}

# Add the AzDO repo as a remote.
git remote add azdo-mirror "https://nibanks:$Env:AzDO_PAT@mscodehub.visualstudio.com/msquic/_git/msquic"

$SourceName = "" # The name of the branch or tag

if ($Source.StartsWith("refs/heads/")) {

    # Remove the 'refs/heads/' prefix.
    $SourceName = $Source.Substring(11)

    # Make sure we're in the correct branch.
    git checkout $SourceName

    # Reset branch to origin.
    git reset --hard origin/$SourceName

} elseif ($Source.StartsWith("refs/tags/")) {

    # Remove the 'refs/tags/' prefix.
    $SourceName = $Source.Substring(10)

    # Make sure we're in the correct tag.
    git checkout $SourceName

} else {
    Write-Error "Unsupported source: " + $Source
}

# Some extra info for debugging failures.
git log -5
git status

# Push to the AzDO repo.
try {
    git push azdo-mirror $SourceName
} catch {
    Write-Host "Supressing exception while running 'git push'"
}

Write-Host "Successfully mirrored latest changes"
