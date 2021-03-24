param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "",
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

if ($IsWindows) {
    $Platform = "windows"
} elseif ($IsLinux) {
    $Platform = "linux"
} elseif ($IsMacOS) {
    $Platform = "macos"
} else {
    Write-Error "Unsupported platform type!"
}

# Relevant file paths used by this script.
$RootDir = Split-Path $PSScriptRoot -Parent
$RootArtifactDir = Join-Path $RootDir "artifacts" "bin" $Platform "$($Arch)_$($Config)_$($Tls)"


