Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'


$RepoRoot = Split-Path $PSScriptRoot -Parent
$OutputPath = Join-Path $RepoRoot "build"

$env:GIT_REDIRECT_STDERR = '2>&1'

function Get-GitRemoteUrl {
    param($RepoRoot)
    return git config --get remote.origin.url
}

function Get-GitCurrentHash {
    param($RepoRoot)
    return git rev-parse --verify HEAD
}

function Invoke-GitSubmoduleForeach {
    param($RepoRoot)
    return git submodule foreach --quiet --recursive '"echo $displaypath,$sha1,`git config --get remote.origin.url`"'
}

function Get-SourceLink {
    param($RepoRoot, $GitRemote, $GitCurrentHash, $Map)

    $LocalPath = Join-Path $RepoRoot "*"
    if (!($GitRemote -match "https://github\.com")) {
        Write-Warning "Unable to sourcelink remote ""$GitRemote"". Unknown host"
        return
    }

    $RawGitUrl = $GitRemote.Replace(".git", "")
    $RawGitUrl = $GitRemote.Replace("github.com", "raw.githubusercontent.com")
    $RawGitUrl += "/$GitCurrentHash/*"
    $Map[$LocalPath] = $RawGitUrl
}

$GitRemote = Get-GitRemoteUrl -RepoRoot $RepoRoot
$GitCurrentHash = Get-GitCurrentHash -RepoRoot $RepoRoot

$Map = @{}

Get-SourceLink -RepoRoot $RepoRoot -GitRemote $GitRemote -GitCurrentHash $GitCurrentHash -Map $Map

$SubmoduleInfo = Invoke-GitSubmoduleForeach -RepoRoot $RepoRoot

foreach ($submodule in $SubmoduleInfo) {
    $Split = $submodule.Split(',', 3)
    $SubRepoRoot = Join-Path $RepoRoot $Split[0]
    Get-SourceLink -RepoRoot $SubRepoRoot -GitRemote $Split[2] -GitCurrentHash $Split[1] -Map $Map
}

$SourceLink = @{ documents = $Map }

New-Item  -ItemType directory -Path $OutputPath -Force | Out-Null
$SourceLinkFile = Join-Path $OutputPath "source_link.json"

$SourceLink | ConvertTo-Json | Out-File $SourceLinkFile
