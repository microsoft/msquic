<#

.SYNOPSIS
This script provides helper functions used by multiple build scripts.

.PARAMETER BuildConfig
    Grab information about the build config

#>

param (
    # Hashtable of Arch, TLS and Platform, and maybe ExtraArtifactDir.
    # No type because custom types can't be passed to scripts
    $BuildConfig = $null
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if ($null -ne $BuildConfig) {
    $Arch = $BuildConfig.Arch
    $Tls = $BuildConfig.Tls
    $Platform = $BuildConfig.Platform
    $ExtraArtifactDir = $BuildConfig.ExtraArtifactDir
    $Config = $BuildConfig.Config

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
}

return "FAILURE"
