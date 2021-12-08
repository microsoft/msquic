<#

.SYNOPSIS
This script automates updating all the necessary files for incrementing the
current version number.

.PARAMETER Part
    Specifies the part of the version number to increment:
    Major, Minor, or Patch

.EXAMPLE
    update-version.ps1 -Part Major

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Major", "Minor", "Patch")]
    [string]$Part
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Relevant file paths used by this script.
$RootDir = Split-Path $PSScriptRoot -Parent
$MsQuicVerFilePath = Join-Path $RootDir "src" "inc" "msquic.ver"
$CreateVPackFilePath = Join-Path $RootDir ".azure" "obtemplates" "push-vpack.yml"
$QnsFilePath = Join-Path $RootDir ".azure" "azure-pipelines.qns.yml"
$NugetPackageFile = Join-Path $RootDir "scripts" "package-nuget.ps1"
$FrameworkInfoFile = Join-Path $RootDir "src" "distribution" "Info.plist"
$VersionsWriteFile = Join-Path $RootDir "scripts" "write-versions.ps1"

# Get the current version number from the msquic.ver file.
$VerMajor = (Select-String -Path $MsQuicVerFilePath "#define VER_MAJOR (.*)" -AllMatches).Matches[0].Groups[1].Value
$VerMinor = (Select-String -Path $MsQuicVerFilePath "#define VER_MINOR (.*)" -AllMatches).Matches[0].Groups[1].Value
$VerPatch = (Select-String -Path $MsQuicVerFilePath "#define VER_PATCH (.*)" -AllMatches).Matches[0].Groups[1].Value
Write-Host "Current version: $VerMajor.$VerMinor.$VerPatch"

$NewVerMajor = [int]$VerMajor;
$NewVerMinor = [int]$VerMinor;
$NewVerPatch = [int]$VerPatch;

# Increment the version number according to the input arg.
switch ($Part) {
    "Major"   { $NewVerMajor = $NewVerMajor + 1; $NewVerMinor = 0; $NewVerPatch = 0 }
    "Minor"   { $NewVerMinor = $NewVerMinor + 1; $NewVerPatch = 0  }
    "Patch"   { $NewVerPatch = $NewVerPatch + 1 }
}
Write-Host "    New version: $NewVerMajor.$NewVerMinor.$NewVerPatch"

# Write the new version to the files.
(Get-Content $MsQuicVerFilePath) `
    -replace "#define VER_MAJOR (.*)", "#define VER_MAJOR $NewVerMajor" `
    -replace "#define VER_MINOR (.*)", "#define VER_MINOR $NewVerMinor" `
    -replace "#define VER_PATCH (.*)", "#define VER_PATCH $NewVerPatch" |`
    Out-File $MsQuicVerFilePath
(Get-Content $CreatePackageFilePath) `
    -replace "majorVer: (.*)", "majorVer: $NewVerMajor" `
    -replace "minorVer: (.*)", "minorVer: $NewVerMinor" `
    -replace "patchVer: (.*)", "patchVer: $NewVerPatch" |`
    Out-File $CreatePackageFilePath
(Get-Content $CreateVPackFilePath) `
    -replace "majorVer: (.*)", "majorVer: $NewVerMajor" `
    -replace "minorVer: (.*)", "minorVer: $NewVerMinor" `
    -replace "patchVer: (.*)", "patchVer: $NewVerPatch" |`
    Out-File $CreateVPackFilePath
(Get-Content $QnsFilePath) `
    -replace "$VerMajor.$VerMinor.$VerPatch", "$NewVerMajor.$NewVerMinor.$NewVerPatch" |`
    Out-File $QnsFilePath
(Get-Content $NugetPackageFile) `
    -replace "$VerMajor.$VerMinor.$VerPatch", "$NewVerMajor.$NewVerMinor.$NewVerPatch" |`
    Out-File $NugetPackageFile
(Get-Content $FrameworkInfoFile) `
    -replace "$VerMajor.$VerMinor.$VerPatch", "$NewVerMajor.$NewVerMinor.$NewVerPatch" |`
    Out-File $FrameworkInfoFile
(Get-Content $VersionsWriteFile) `
    -replace "$VerMajor.$VerMinor.$VerPatch", "$NewVerMajor.$NewVerMinor.$NewVerPatch" |`
    Out-File $VersionsWriteFile
