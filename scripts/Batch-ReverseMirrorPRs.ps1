<#
.SYNOPSIS
    Finds and mirrors all dependabot pull requests from ADO to GitHub.

.DESCRIPTION
    Queries Azure DevOps for active pull requests with source branches matching
    a dependabot pattern, then invokes Create-ReverseMirrorPR.ps1 for each one.
    Since Create-ReverseMirrorPR.ps1 abandons the ADO PR after mirroring, this
    script is idempotent — re-running it will only process new (unmirrored) PRs.

.PARAMETER AdoOrg
    The Azure DevOps organization name. Defaults to 'microsoft'.

.PARAMETER AdoProject
    The Azure DevOps project name. Defaults to 'undock'.

.PARAMETER AdoRepo
    The Azure DevOps repository name. Defaults to 'msquic'.

.PARAMETER GitHubOrg
    The GitHub organization name. Defaults to 'microsoft'.

.PARAMETER GitHubRepo
    The GitHub repository name. Defaults to 'msquic'.

.PARAMETER AdoRemote
    The git remote name for ADO. Defaults to 'undock'.

.PARAMETER GitHubRemote
    The git remote name for GitHub. Defaults to 'origin'.

.PARAMETER BranchPattern
    Regex pattern to match dependabot source branches. Defaults to '^dependabot/'.

.PARAMETER TargetBranch
    Only mirror PRs targeting this branch. If empty, mirrors PRs targeting any branch.

.PARAMETER DryRun
    List matching PRs without mirroring them.

.EXAMPLE
    .\Batch-ReverseMirrorPrs.ps1
    # Finds and mirrors all active dependabot PRs from ADO to GitHub.

.EXAMPLE
    .\Batch-ReverseMirrorPrs.ps1 -DryRun
    # Lists all active dependabot PRs without mirroring.

.EXAMPLE
    .\Batch-ReverseMirrorPrs.ps1 -TargetBranch main
    # Only mirrors dependabot PRs targeting the 'main' branch.

.EXAMPLE
    .\Batch-ReverseMirrorPrs.ps1 -BranchPattern '^dependabot/cargo'
    # Only mirrors cargo/Rust dependabot PRs.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$AdoOrg = "microsoft",

    [Parameter(Mandatory = $false)]
    [string]$AdoProject = "undock",

    [Parameter(Mandatory = $false)]
    [string]$AdoRepo = "msquic",

    [Parameter(Mandatory = $false)]
    [string]$GitHubOrg = "microsoft",

    [Parameter(Mandatory = $false)]
    [string]$GitHubRepo = "msquic",

    [Parameter(Mandatory = $false)]
    [string]$AdoRemote = "undock",

    [Parameter(Mandatory = $false)]
    [string]$GitHubRemote = "origin",

    [Parameter(Mandatory = $false)]
    [string]$BranchPattern = '^dependabot/',

    [Parameter(Mandatory = $false)]
    [string]$TargetBranch = "",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MirrorScript = Join-Path $ScriptDir "Create-ReverseMirrorPR.ps1"

if (-not (Test-Path $MirrorScript)) {
    Write-Error "Mirror script not found: $MirrorScript"
    exit 1
}

# Check for required tools
$RequiredTools = @('az', 'gh', 'git')
foreach ($tool in $RequiredTools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "Required tool '$tool' not found. Please install it first."
        exit 1
    }
}

# Verify Azure DevOps authentication
Write-Host "Checking Azure DevOps authentication..." -ForegroundColor Yellow
try {
    $null = az account show 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Logging into Azure DevOps..." -ForegroundColor Yellow
        az login | Out-Null
    }
} catch {
    Write-Error "Failed to authenticate with Azure DevOps: $_"
    exit 1
}

# Verify GitHub authentication
Write-Host "Checking GitHub authentication..." -ForegroundColor Yellow
$null = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Please login to GitHub..." -ForegroundColor Yellow
    gh auth login
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to authenticate with GitHub"
        exit 1
    }
}

# Query ADO for all active pull requests
Write-Host "`nQuerying ADO for active pull requests..." -ForegroundColor Cyan
$adoOrgUrl = "https://dev.azure.com/$AdoOrg"
$prListJson = az repos pr list `
    --organization $adoOrgUrl `
    --project $AdoProject `
    --repository $AdoRepo `
    --status active `
    --top 500 `
    --output json
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to list ADO pull requests"
    exit 1
}

$allPrs = @($prListJson | ConvertFrom-Json)

if ($allPrs.Count -eq 0) {
    Write-Host "No active pull requests found in ADO." -ForegroundColor Green
    exit 0
}

Write-Host "  Found $($allPrs.Count) active PR(s) total." -ForegroundColor Gray

# Filter for dependabot PRs by source branch pattern
$dependabotPrs = $allPrs | Where-Object {
    $branch = $_.sourceRefName -replace '^refs/heads/', ''
    $branch -match $BranchPattern
}

# Optionally filter by target branch
if ($TargetBranch) {
    $dependabotPrs = $dependabotPrs | Where-Object {
        $target = $_.targetRefName -replace '^refs/heads/', ''
        $target -eq $TargetBranch
    }
}

if (-not $dependabotPrs -or $dependabotPrs.Count -eq 0) {
    Write-Host "No dependabot pull requests found matching pattern '$BranchPattern'." -ForegroundColor Green
    exit 0
}

# Force array for single-result case
$dependabotPrs = @($dependabotPrs)

Write-Host "`nFound $($dependabotPrs.Count) dependabot PR(s) to mirror:" -ForegroundColor Cyan
foreach ($pr in $dependabotPrs) {
    $branch = $pr.sourceRefName -replace '^refs/heads/', ''
    $target = $pr.targetRefName -replace '^refs/heads/', ''
    Write-Host "  PR #$($pr.pullRequestId): $($pr.title)" -ForegroundColor White
    Write-Host "    Branch: $branch -> $target" -ForegroundColor Gray
    Write-Host "    Author: $($pr.createdBy.displayName)" -ForegroundColor Gray
}

if ($DryRun) {
    Write-Host "`n[DRY RUN] No PRs were mirrored. Remove -DryRun to mirror." -ForegroundColor Yellow
    exit 0
}

# Mirror each PR
Write-Host "`nMirroring PRs..." -ForegroundColor Cyan
$succeeded = @()
$failed = @()

foreach ($pr in $dependabotPrs) {
    $prId = $pr.pullRequestId
    $branch = $pr.sourceRefName -replace '^refs/heads/', ''
    Write-Host "`n$('=' * 60)" -ForegroundColor DarkGray
    Write-Host "Mirroring PR #$prId ($branch)..." -ForegroundColor Cyan
    Write-Host "$('=' * 60)" -ForegroundColor DarkGray

    try {
        & $MirrorScript `
            -PullRequest $prId `
            -AdoOrg $AdoOrg `
            -AdoProject $AdoProject `
            -AdoRepo $AdoRepo `
            -GitHubOrg $GitHubOrg `
            -GitHubRepo $GitHubRepo `
            -AdoRemote $AdoRemote `
            -GitHubRemote $GitHubRemote
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "Mirror script exited with code $LASTEXITCODE"
        }
        $succeeded += $prId
    } catch {
        Write-Warning "Failed to mirror PR #$prId`: $_"
        $failed += $prId
    }
}

# Print summary
Write-Host "`n$('=' * 60)" -ForegroundColor DarkGray
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "$('=' * 60)" -ForegroundColor DarkGray
Write-Host "  Total:     $($dependabotPrs.Count)" -ForegroundColor White
Write-Host "  Succeeded: $($succeeded.Count)" -ForegroundColor Green
if ($failed.Count -gt 0) {
    Write-Host "  Failed:    $($failed.Count) (PR IDs: $($failed -join ', '))" -ForegroundColor Red
} else {
    Write-Host "  Failed:    0" -ForegroundColor Green
}

if ($failed.Count -gt 0) {
    exit 1
}
