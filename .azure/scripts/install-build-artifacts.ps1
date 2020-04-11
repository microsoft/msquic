<#

.SYNOPSIS
Installs the build artifacts on a test machine.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.EXAMPLE
    install-build-artifacts.ps1

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $true)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch,

    [Parameter(Mandatory = $true)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls
    )

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Important directories.
$RootDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$ArtifactsDir = Join-Path $RootDir "artifacts"

if ($IsWindows) {

} elseif ($IsLinux) {
    # TODO - Figure out how to install openssl?

    # Make sure we have full permissions for all artifacts.
    Write-Host "[$(Get-Date)] Configuring permissions for artifacts..."
    sudo chmod -R 777 $ArtifactsDir
}
