<#

.SYNOPSIS
    This script assembles darwin frameworks into an xcframework

.PARAMETER Config
    The debug or release configuration to build for.

.PARAMETER Tls
    The TLS library to use.
#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("quictls", "openssl")]
    [string]$Tls = "quictls"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if (!$IsMacOS) {
    Write-Error "This script can only be ran on macOS"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$FrameworkDir = Join-Path $RootDir artifacts frameworks

$IosSimulatorFramework = Join-Path $FrameworkDir ios x64_$($Config)_$($Tls) msquic.framework
$IosFramework = Join-Path $FrameworkDir ios arm64_$($Config)_$($Tls) msquic.framework
$MacFramework = Join-Path $FrameworkDir macos universal_$($Config)_$($Tls) msquic.framework

$OutputDirectory = Join-Path $FrameworkDir msquic.xcframework

xcodebuild -create-xcframework -framework $IosSimulatorFramework -framework $IosFramework -framework $MacFramework -output $OutputDirectory
