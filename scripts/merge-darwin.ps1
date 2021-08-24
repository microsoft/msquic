<#

.SYNOPSIS
This script merges all darwin artifacts into universal binaries

.PARAMETER Config
    The debug or release configuration to merge.

.PARAMETER Tls
    The TLS library to of the binaries to merge.

.EXAMPLE
    build.ps1

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("openssl")]
    [string]$Tls = "openssl",

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir,

    [Parameter(Mandatory = $false)]
    [switch]$DeleteSource = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if (!$IsMacOS) {
    Write-Error "This script can only be ran on macOS"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Important directory paths.
$BaseArtifactsDir = Join-Path $RootDir "artifacts"

$ArtifactsDir = Join-Path $BaseArtifactsDir "bin" "macos"

if ([string]::IsNullOrWhitespace($ExtraArtifactDir)) {
    $X64ArtifactsDir = Join-Path $ArtifactsDir "x64_$($Config)_$($Tls)"
    $Arm64ArtifactsDir = Join-Path $ArtifactsDir "arm64_$($Config)_$($Tls)"
    $UniversalArtifactsDir = Join-Path $ArtifactsDir "universal_$($Config)_$($Tls)"
} else {
    $X64ArtifactsDir = Join-Path $ArtifactsDir "x64_$($Config)_$($Tls)_$($ExtraArtifactDir)"
    $Arm64ArtifactsDir = Join-Path $ArtifactsDir "arm64_$($Config)_$($Tls)_$($ExtraArtifactDir)"
    $UniversalArtifactsDir = Join-Path $ArtifactsDir "universal_$($Config)_$($Tls)_$($ExtraArtifactDir)"
}

New-Item $UniversalArtifactsDir -ItemType Directory -Force | Out-Null

$X64Artifacts = Get-ChildItem -Path $X64ArtifactsDir

foreach ($X64Artifact in $X64Artifacts) {
    $ArmArtifact = Join-Path $Arm64ArtifactsDir $X64Artifact.Name
    if (!(Test-Path $ArmArtifact)) {
        Write-Output "Missing $($X64Artifact.Name). Skipping"
        continue
    }
    $UniversalArtifact = Join-Path $UniversalArtifactsDir $X64Artifact.Name

    lipo -create -output $UniversalArtifact $X64Artifact $ArmArtifact
}

if ($DeleteSource) {
    Remove-Item -Path $X64ArtifactsDir -Recurse -Force
    Remove-Item -Path $Arm64ArtifactsDir -Recurse -Force
}
