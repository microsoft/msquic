<#

.SYNOPSIS
This script provides a build config helper used by multiple build scripts.

.PARAMETER Config
    The debug or release configuration to build for.

.PARAMETER Arch
    The CPU architecture to build for.

.PARAMETER Platform
    Specify which platform to build for

.PARAMETER Tls
    The TLS library to use.

.PARAMETER ExtraArtifactDir
    Add an extra classifier to the artifact directory to allow publishing alternate builds of same base library

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64", "arm64ec", "universal", "")]
    [string]$Arch = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("gamecore_console", "uwp", "windows", "linux", "macos", "android", "ios", "")] # For future expansion
    [string]$Platform = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if ($Platform -eq "android") {
    if (!$IsLinux) {
        Write-Error "Can only build android on linux"
    }
    if ($Arch -eq "") {
        $Arch = "arm64"
    }
}

if ($Platform -eq "ios") {
    if (!$IsMacOS) {
        Write-Error  "Can only build ios on macOS"
    }
    if ($Arch -eq "") {
        $Arch = "arm64"
    }
}

if ("" -eq $Arch) {
    if ($IsMacOS) {
        $RunningArch = uname -m
        if ("x86_64" -eq $RunningArch) {
            $IsTranslated = sysctl -in sysctl.proc_translated
            if ($IsTranslated) {
                $Arch = "arm64"
            } else {
                $Arch = "x64"
            }
        } elseif ("arm64" -eq $RunningArch) {
            $Arch = "arm64"
        } else {
            Write-Error "Unknown architecture"
        }
    } else {
        $Arch = "x64"
    }
}

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

if ("" -eq $Platform) {
    if ($IsWindows) {
        $Platform = "windows"
    } elseif ($IsLinux) {
        $Platform = "linux"
    } elseif ($IsMacOS) {
        $Platform = "macos"
    } else {
        Write-Error "Unsupported platform type!"
    }
}

$RootDir = Split-Path $PSScriptRoot -Parent
$BaseArtifactsDir = Join-Path $RootDir "artifacts"
$ArtifactsDir = Join-Path $BaseArtifactsDir "bin" $Platform
if ([string]::IsNullOrWhitespace($ExtraArtifactDir)) {
    $ArtifactsDir = Join-Path $ArtifactsDir "$($Arch)_$($Config)_$($Tls)"
} else {
    $ArtifactsDir = Join-Path $ArtifactsDir "$($Arch)_$($Config)_$($Tls)_$($ExtraArtifactDir)"
}

return @{
    Platform = $Platform
    Tls = $Tls
    Arch = $Arch
    ArtifactsDir = $ArtifactsDir
}
