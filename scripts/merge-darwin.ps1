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
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if (!$IsMacOS) {
    Write-Error "This script can only be ran on macOS"
}

if ("" -eq $Tls) {
    $Tls = "openssl"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Important directory paths.
$BaseArtifactsDir = Join-Path $RootDir "artifacts"

$ArtifactsDir = Join-Path $BaseArtifactsDir "bin" "macos"

$X64ArtifactsDir = Join-Path $ArtifactsDir "x64_$($Config)_$($Tls)"
$Arm64ArtifactsDir = Join-Path $ArtifactsDir "arm64_$($Config)_$($Tls)"
$UniversalArtifactsDir = Join-Path $ArtifactsDir "universal_$($Config)_$($Tls)"

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
