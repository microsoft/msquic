<#

.SYNOPSIS
This synchronizes all the changes from mirror branch to the integration branch.

.EXAMPLE
    integrate-branch.ps1

.EXAMPLE
    integrate-branch.ps1 -Branch refs/heads/release/xxxx

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$Branch = "refs/heads/main"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Redirect stderr to stdout for git.
$env:GIT_REDIRECT_STDERR = '2>&1'

# Set identity for any git commands that need it.
git config user.email "quicdev@microsoft.com"
git config user.name "QUIC Dev Bot"

# Remove the 'refs/heads/' prefix.
$MirrorBranch = $Branch.Substring(11)

# The integration branch is just the mirror branch prefixed with "integration/"
$IntegrationBranch = "integration/$MirrorBranch"

Write-Host "`n== Integrating changes in $MirrorBranch to $IntegrationBranch =="

# Make sure we can checkout the mirror branch.
Write-Host "`n== Checking out $MirrorBranch =="
git checkout $MirrorBranch
"LASTEXITCODE=$LASTEXITCODE"
if ($LASTEXITCODE) { Write-Error "Checkout mirror branch failed!" }

# Try to checkout the existing branch.
Write-Host "`n== Checking out $IntegrationBranch =="
git checkout $IntegrationBranch
"LASTEXITCODE=$LASTEXITCODE"

if ($LASTEXITCODE) {
    # Failed to checkout existing branch, so create it and push it upstream.
    Write-Host "`n== Creating $IntegrationBranch =="
    git checkout -b $IntegrationBranch
    "LASTEXITCODE=$LASTEXITCODE"
    if ($LASTEXITCODE) { Write-Error "Create branch failed!" }

    Write-Host "`n== Setting $IntegrationBranch upstream =="
    git push --set-upstream origin $IntegrationBranch
    "LASTEXITCODE=$LASTEXITCODE"
    if ($LASTEXITCODE) { Write-Error "Push branch failed!" }

} else {
    # Checkout successful. Merge the mirror changes.
    Write-Host "`n== Merging $MirrorBranch into $IntegrationBranch =="
    git merge $MirrorBranch
    "LASTEXITCODE=$LASTEXITCODE"
    if ($LASTEXITCODE) {
        git merge --abort
        Write-Error "Merge Failed! Run and handle the merge conflicts:`n`ngit checkout $IntegrationBranch`ngit merge $MirrorBranch`n"
    }

    # Push the changes upstream.
    Write-Host "`n== Pushing $IntegrationBranch upstream =="
    git push
    "LASTEXITCODE=$LASTEXITCODE"
    if ($LASTEXITCODE) { Write-Error "Push branch failed!" }
}

Write-Host "`n== Integration complete =="
