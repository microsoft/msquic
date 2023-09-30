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
    [ValidateSet("x86", "x64", "arm", "arm64", "universal")]
    [string]$Arch,

    [Parameter(Mandatory = $true)]
    [ValidateSet("schannel", "openssl", "openssl3")]
    [string]$Tls
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Important directories.
$RootDir = Split-Path $PSScriptRoot -Parent
$ArtifactsDir = Join-Path $RootDir "artifacts/bin"

if ($IsWindows) {
    if (!(Test-Path "C:\Windows\System32\drivers\msquic.sys")) {
        # Install ETW manifest, if not already present
        $MsQuicDll = Join-Path $ArtifactsDir "\windows\$($Arch)_$($Config)_$($Tls)\msquic.dll"
        $ManifestPath = Join-Path $RootDir "\src\manifest\MsQuicEtw.man"
        $Command = "wevtutil.exe im $($ManifestPath) /rf:$($MsQuicDll) /mf:$($MsQuicDll)"
        Write-Host $Command
        Invoke-Expression $Command
    }

} elseif ($IsLinux -or $IsMacOS) {
    # TODO - Figure out how to install openssl?

    # Make sure we have full permissions for all artifacts.
    Write-Host "[$(Get-Date)] Configuring permissions for artifacts..."
    sudo chmod -R 777 $ArtifactsDir
}
