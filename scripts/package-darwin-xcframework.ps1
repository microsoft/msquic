<#

.SYNOPSIS
    This script assembles darwin frameworks into an xcframework

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if (!$IsMacOS) {
    Write-Error "This script can only be ran on macOS"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$FrameworkDir = Join-Path $RootDir artifacts frameworks

$IosSimulatorFramework = Join-Path $FrameworkDir ios x64_$($Config)_openssl msquic.framework
$IosFramework = Join-Path $FrameworkDir ios arm64_$($Config)_openssl msquic.framework
$MacFramework = Join-Path $FrameworkDir macos universal_$($Config)_openssl msquic.framework

$OutputDirectory = Join-Path $FrameworkDir msquic.xcframework

xcodebuild -create-xcframework -framework $IosSimulatorFramework -framework $IosFramework -framework $MacFramework -output $OutputDirectory
