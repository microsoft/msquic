<#
.SYNOPSIS
    Mirrors an internal ADO pull request to GitHub.

.DESCRIPTION
    Takes an internal Azure DevOps pull request, fetches the branch locally,
    pushes it to GitHub, creates a corresponding GitHub pull request, and
    then abandons the ADO pull request with a comment linking to the GitHub PR.

.PARAMETER PullRequest
    The ADO pull request ID or URL to mirror.

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

.EXAMPLE
    .\Create-ReverseMirrorPR.ps1 -PullRequest 12345

.EXAMPLE
    .\Create-ReverseMirrorPR.ps1 -PullRequest "https://dev.azure.com/microsoft/OS/_git/msquic/pullrequest/12345"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$PullRequest,

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
    [string]$GitHubRemote = "origin"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Parse PR ID from URL if needed
$PrId = $PullRequest
if ($PullRequest -match 'pullrequest[/]?(\d+)') {
    $PrId = $Matches[1]
}

Write-Host "Processing ADO Pull Request ID: $PrId" -ForegroundColor Cyan

# Check for required tools
$RequiredTools = @('az', 'gh', 'git')
foreach ($tool in $RequiredTools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Error "Required tool '$tool' not found. Please install it first."
        exit 1
    }
}

# Ensure we're logged into Azure DevOps
Write-Host "Checking Azure DevOps authentication..." -ForegroundColor Yellow
try {
    az devops configure --defaults organization="https://dev.azure.com/$AdoOrg" project=$AdoProject | Out-Null
    $null = az account show 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Logging into Azure DevOps..." -ForegroundColor Yellow
        az login | Out-Null
    }
} catch {
    Write-Error "Failed to authenticate with Azure DevOps: $_"
    exit 1
}

# Ensure we're logged into GitHub
Write-Host "Checking GitHub authentication..." -ForegroundColor Yellow
$ghStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Please login to GitHub..." -ForegroundColor Yellow
    gh auth login
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to authenticate with GitHub"
        exit 1
    }
}

# Get ADO PR details
Write-Host "Fetching ADO pull request details..." -ForegroundColor Yellow
$prJson = az repos pr show --id $PrId --organization "https://dev.azure.com/$AdoOrg" --output json
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to fetch ADO pull request details"
    exit 1
}

$adoPr = $prJson | ConvertFrom-Json

$sourceBranch = $adoPr.sourceRefName -replace '^refs/heads/', ''
$targetBranch = $adoPr.targetRefName -replace '^refs/heads/', ''
$prTitle = "[Mirror #$PrId] $($adoPr.title)"
$prAuthor = $adoPr.createdBy.displayName

Write-Host "  Title: $prTitle" -ForegroundColor Gray
Write-Host "  Source Branch: $sourceBranch" -ForegroundColor Gray
Write-Host "  Target Branch: $targetBranch" -ForegroundColor Gray
Write-Host "  Author: $prAuthor" -ForegroundColor Gray

# Ensure git remotes are configured
Write-Host "Configuring git remotes..." -ForegroundColor Yellow
$currentRemotes = git remote
if ($currentRemotes -notcontains $AdoRemote) {
    Write-Host "  Adding ADO remote '$AdoRemote'..." -ForegroundColor Gray
    git remote add $AdoRemote "https://dev.azure.com/$AdoOrg/$AdoProject/_git/$AdoRepo"
}
if ($currentRemotes -notcontains $GitHubRemote) {
    Write-Host "  Adding GitHub remote '$GitHubRemote'..." -ForegroundColor Gray
    git remote add $GitHubRemote "https://github.com/$GitHubOrg/$GitHubRepo.git"
}

# Fetch the source branch from ADO
Write-Host "Fetching branch from ADO..." -ForegroundColor Yellow
git fetch $AdoRemote "${sourceBranch}:${sourceBranch}" --force
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to fetch branch '$sourceBranch' from ADO"
    exit 1
}

# Push the branch to GitHub
Write-Host "Pushing branch to GitHub..." -ForegroundColor Yellow
git push $GitHubRemote "${sourceBranch}:${sourceBranch}" --force
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to push branch '$sourceBranch' to GitHub"
    exit 1
}

# Create GitHub pull request
Write-Host "Creating GitHub pull request..." -ForegroundColor Yellow
$adoPrUrl = "https://dev.azure.com/$AdoOrg/$AdoProject/_git/$AdoRepo/pullrequest/$PrId"
$ghPrBody = @"
Mirrored from internal ADO PR #$PrId by $prAuthor

Internal PR: $adoPrUrl
"@
$ghPrOutput = gh pr create --repo "$GitHubOrg/$GitHubRepo" --base $targetBranch --head $sourceBranch --title $prTitle --body $ghPrBody 2>&1
if ($LASTEXITCODE -ne 0) {
    # Check if PR already exists
    if ($ghPrOutput -match 'already exists') {
        Write-Host "  Pull request already exists, fetching URL..." -ForegroundColor Yellow
        $existingPrs = gh pr list --repo "$GitHubOrg/$GitHubRepo" --head $sourceBranch --base $targetBranch --json url --jq '.[0].url'
        if ($existingPrs) {
            $githubPrUrl = $existingPrs
            Write-Host "  Using existing PR: $githubPrUrl" -ForegroundColor Green
        } else {
            Write-Error "Failed to find existing GitHub pull request"
            exit 1
        }
    } else {
        Write-Error "Failed to create GitHub pull request: $ghPrOutput"
        exit 1
    }
} else {
    $githubPrUrl = $ghPrOutput
    Write-Host "  Created: $githubPrUrl" -ForegroundColor Green
}

# Add comment to ADO PR with GitHub PR link
Write-Host "Adding comment to ADO pull request..." -ForegroundColor Yellow
$comment = "This pull request has been mirrored to GitHub: $githubPrUrl`n`nPlease continue all review and development on the GitHub pull request."
$repositoryId = $adoPr.repository.id
$threadBody = @{
    comments = @(
        @{
            parentCommentId = 0
            content = $comment
            commentType = 1
        }
    )
    status = 1
} | ConvertTo-Json -Depth 10

$tempFile = [System.IO.Path]::GetTempFileName()
try {
    $threadBody | Out-File -FilePath $tempFile -Encoding utf8 -NoNewline
    $commentResult = az devops invoke --http-method POST --organization "https://dev.azure.com/$AdoOrg" --area git --resource pullRequestThreads --route-parameters project=$AdoProject repositoryId=$repositoryId pullRequestId=$PrId --api-version 6.0 --in-file $tempFile 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to add comment thread to ADO pull request: $commentResult"
    }
} finally {
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
}

# Abandon the ADO pull request
Write-Host "Abandoning ADO pull request..." -ForegroundColor Yellow
az repos pr update --id $PrId --organization "https://dev.azure.com/$AdoOrg" --status abandoned | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to abandon ADO pull request"
    exit 1
}

Write-Host "`nSuccess! ADO PR #$PrId has been mirrored to GitHub and abandoned." -ForegroundColor Green
Write-Host "GitHub PR: $githubPrUrl" -ForegroundColor Cyan
