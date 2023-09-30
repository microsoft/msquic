<#

.SYNOPSIS
This script commits new PGD files and creates a PR to ingest into MsQuic.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    Specifies what the CPU arch is
#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [string]$BuildNumber = "$(get-date -format 'yyyy-MM-dd')"
)

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
Write-Debug "Rootdir is $($RootDir)"

git config --global credential.helper store
Set-Content -Path "$env:HOME\.git-credentials" -Value "https://$($env:MAPPED_DEPLOYMENT_KEY):x-oauth-basic@github.com`n" -NoNewLine

# Set Git Config Info.
git config user.email "quicdev@microsoft.com"
git config user.name "QUIC Dev[bot]"

# Make the branch.
$BranchName = "merge-pgo-$($BuildNumber)"
git fetch
git checkout main
git checkout -b $BranchName

Copy-Item -Path artifacts/PerfDataResults/performance/windows/$($Arch)_$($Config)_schannel/msquic.pgd src/bin/winuser/pgo_$($Arch)/msquic.schannel.pgd -Force
Copy-Item -Path artifacts/PerfDataResults/performance/windows/$($Arch)_$($Config)_openssl/msquic.pgd src/bin/winuser/pgo_$($Arch)/msquic.openssl.pgd -Force
Copy-Item -Path artifacts/PerfDataResults/performance/windows/$($Arch)_$($Config)_openssl3/msquic.pgd src/bin/winuser/pgo_$($Arch)/msquic.openssl3.pgd -Force

# Commit the new PGD files.
git commit -am "Update PGO data"
git push --set-upstream origin $BranchName

# Make the PR with GitHub REST API and add tags to it.
$Headers = @{
  'Accept' = 'application/vnd.github+json'
  'Authorization' = "token $($env:MAPPED_DEPLOYMENT_KEY)"
}
$Uri = "https://api.github.com/repos/microsoft/msquic/pulls"
$Body = @{
  'title' = '[Automated] Update PGO'
  'head' = "$($BranchName)"
  'base' = 'main'
  'body' = 'Update the PGO database with the latest perf numbers'
  'maintainer_can_modify' = $True
}
$Result = Invoke-RESTMethod -Uri $Uri -Headers $Headers -Body ($Body | ConvertTo-Json) -ContentType "application/json" -Method Post
Write-Debug $Result
$Number = ($Result | Select-Object -Property 'number')

$Uri = "https://api.github.com/repos/microsoft/msquic/issues/$($Number.number)/labels"
$Body = @{
  'labels' = 'Area: Automation','Area: Performance'
}
$Result = Invoke-RESTMethod -Uri $Uri -Headers $Headers -Body ($Body | ConvertTo-Json) -ContentType "application/json" -Method Post
