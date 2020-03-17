<#

.SYNOPSIS
This script installs all necessary dependencies on the machine, depending
on the provided configuration.

.PARAMETER Configuration
    The type of configuration to install dependencies for.

.EXAMPLE
    prepare-machine.ps1 -Configuration Build

.EXAMPLE
    prepare-machine.ps1 -Configuration Test

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Build", "Test", "Dev")]
    [string]$Configuration
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Important directories.
$RootDir = Split-Path $PSScriptRoot -Parent
$ScriptsDir = Join-Path $RootDir ".azure" "scripts"

if ($IsWindows) {

    if ($Configuration -eq "Dev") {
        # TODO - Support installing VS and necessary addins
        # TODO - Install CMake
        # TODO - Check for Windows preview
    }

    if ($Configuration -eq "Test" -or $Configuration -eq "Dev") {
        # Disable SChannel TLS 1.3 (client and server).
        $TlsServerKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
        reg.exe add $TlsServerKeyPath /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add $TlsServerKeyPath /v Enabled /t REG_DWORD /d 0 /f | Out-Null
        $TlsClientKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
        reg.exe add $TlsClientKeyPath /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add $TlsClientKeyPath /v Enabled /t REG_DWORD /d 0 /f | Out-Null
    
        # Run procdump installation script.
        & (Join-Path $ScriptsDir "install-procdump.ps1")
    
        # Enable SChannel TLS 1.3 (client and server).
        $TlsServerKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
        reg.exe add $TlsServerKeyPath /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add $TlsServerKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null
        $TlsClientKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
        reg.exe add $TlsClientKeyPath /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add $TlsClientKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null
    }

} else {
    switch ($Configuration) {
        "Build" {
            sudo apt-get install liblttng-ust-dev
        }
        "Test" {
            sudo apt-get install lttng-tools

            # Enable core dumps for the system.
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
        "Dev" {
            sudo apt-get install cmake
            sudo apt-get install build-essentials
            sudo apt-get install liblttng-ust-dev
            sudo apt-get install lttng-tools
        }
    }
}
