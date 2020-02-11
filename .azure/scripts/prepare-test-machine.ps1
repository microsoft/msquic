<#

.SYNOPSIS
Prepares the local machine for testing.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.PARAMETER InstallManifest
    Installs the Windows ETW manifest on the test machine.

.EXAMPLE
    prepare-test-machine.ps1

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "schannel",

    [Parameter(Mandatory = $false)]
    [switch]$InstallManifest = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Other important directories.
$ScriptsDir = Join-Path $RootDir ".azure" "scripts"
$ArtifactsDir = Join-Path $RootDir "artifacts"

if ($IsWindows) {
    # Run procdump installation script.
    & (Join-Path $ScriptsDir "install-procdump.ps1")

    if ($InstallManifest) {
        # Install ETW manifest
        $MsQuicDll = Join-Path $ArtifactsDir "\windows\$($Arch)_$($Config)_$($Tls)\msquic.dll"
        $ManifestPath = Join-Path $RootDir "\src\manifest\MsQuicEtw.man"
        $Arguments = "$($ManifestPath) /rf:$($MsQuicDll) /mf:$($MsQuicDll)"
        & wevtutil.exe $Arguments
    }

    # Enable SChannel TLS 1.3 (client and server).
    $TlsServerKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
    reg.exe add $TlsServerKeyPath /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add $TlsServerKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null
    $TlsClientKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
    reg.exe add $TlsClientKeyPath /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
    reg.exe add $TlsClientKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null

} elseif ($IsLinux) {

    # Make sure we have full permissions for all artifacts.
    Write-Host "[$(Get-Date)] Configuring permissions for artifacts..."
    sudo chmod -R 777 $ArtifactsDir

    # Enable core dumps (up to ~1GB) for the system.
    Write-Host "[$(Get-Date)] Setting core dump size limit..."
    sudo sh -c "echo 'root soft core unlimited' >> /etc/security/limits.conf"
    sudo sh -c "echo 'root hard core unlimited' >> /etc/security/limits.conf"
    sudo sh -c "echo '* soft core unlimited' >> /etc/security/limits.conf"
    sudo sh -c "echo '* hard core unlimited' >> /etc/security/limits.conf"
    #sudo cat /etc/security/limits.conf

    # Set the core dump pattern.
    Write-Host "[$(Get-Date)] Setting core dump pattern..."
    sudo sh -c "echo -n '%e.%p.%t.core' > /proc/sys/kernel/core_pattern"
    #sudo cat /proc/sys/kernel/core_pattern
}
