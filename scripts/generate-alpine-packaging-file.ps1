param (
    [Parameter(Mandatory = $false)]
    [string]$ArchiveUri = 'https://github.com/microsoft/msquic/archive/refs/tags/v$pkgver.tar.gz',

    [Parameter(Mandatory = $false)]
    [string]$SHA = ""
)

class Version
{
    [string]$Major
    [string]$Minor
    [string]$Patch
}

$submodules = git submodule

$processedSubmodules = @("clog", "openssl3", "googletest")
$placeholderVariables = @{
    "clog" = "CLOG_COMMIT_HASH"
    "openssl3" = "OPENSSL3_COMMIT_HASH"
    "googletest" = "GOOGLETEST_COMMIT_HASH"
}
$versionPlaceholder = "VERSION_PLACEHOLDER"
$alpinePackagingFile = ((Get-Content "$PSScriptRoot/templates/APKBUILD.template") -join "`n") + "`n"
$alpinePackagingFile = $alpinePackagingFile -replace "ARCHIVE_URI_PLACEHOLDER", $ArchiveUri

if ($SHA -ne "")
{
    $alpinePackagingFile = $alpinePackagingFile -replace "SHA_PLACEHOLDER", $SHA
}
else
{
    $alpinePackagingFile = $alpinePackagingFile -replace "SHA_PLACEHOLDER", '$pkgver'
}

foreach ($submodule in $submodules)
{
    $submoduleInfo = $submodule.Trim().Trim('-').Split(" ")
    $submoduleName = $submoduleInfo[1].Replace("submodules/", "")
    if ($processedSubmodules -contains $submoduleName)
    {
        $alpinePackagingFile = $alpinePackagingFile -replace $placeholderVariables[$submoduleName], $submoduleInfo[0]
    }
}

$version = [Version](Get-Content "$PSScriptRoot/../version.json" | Out-String | ConvertFrom-Json)
$alpinePackagingFile = $alpinePackagingFile -replace $versionPlaceholder, "$($version.Major).$($version.Minor).$($version.Patch)"
Write-Output $alpinePackagingFile | Out-File APKBUILD -NoNewline
Write-Output "APKBUILD file for msquic v$($version.Major).$($version.Minor).$($version.Patch) has been generated successfully."
Write-Output "Starting to add file hashes into APKBUILD file..."

docker run -v .:/msquic -w /msquic alpine:latest /msquic/scripts/alpine-generate-hash.sh
Write-Output "File hashes have been added successfully."
