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

#Requires -RunAsAdministrator

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$NuGetPath = Join-Path $RootDir "nuget"

function Install-ClogTool {
    param($NuGetName, $ToolName, $DownloadUrl)
    New-Item -Path $NuGetPath -ItemType Directory -Force | Out-Null
    $NuGetFile = Join-Path $NuGetPath $NuGetName
    $OldProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri "$DownloadUrl/$NuGetName" -OutFile $NuGetFile
        dotnet tool install --global --add-source $NuGetPath $ToolName
    } catch {
        Write-Warning "Clog could not be installed. Building with logs will not work"
    } finally {
        $ProgressPreference = $OldProgressPreference
    }
}

if (($Configuration -eq "Dev") -or ($Configuration -eq "Build")) {
        $NuGetName = "Microsoft.Logging.CLOG.0.1.1.nupkg"
        $ToolName = "Microsoft.Logging.CLOG"
        $DownloadUrl = "https://github.com/microsoft/CLOG/releases/download/v0.1.1"
        Install-ClogTool -NuGetName $NuGetName -ToolName $ToolName -DownloadUrl $DownloadUrl
}

if ($IsWindows) {

    if ($Configuration -eq "Dev") {
        # TODO - Support installing VS and necessary addins
        # TODO - Install CMake
        # TODO - Check for Windows preview
        # Enable SChannel TLS 1.3 (client and server). Unnecessary on most recent builds.
        $TlsServerKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
        reg.exe add $TlsServerKeyPath /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add $TlsServerKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null
        $TlsClientKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
        reg.exe add $TlsClientKeyPath /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
        reg.exe add $TlsClientKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null
    }
    if ($Configuration -eq "Test") {
        $NuGetName = "Microsoft.Logging.CLOG2Text.Windows.0.1.1.nupkg"
        $ToolName = "Microsoft.Logging.CLOG2Text.Windows"
        $DownloadUrl = "https://github.com/microsoft/CLOG/releases/download/v0.1.1"
        Install-ClogTool -NuGetName $NuGetName -ToolName $ToolName -DownloadUrl $DownloadUrl
    }

} else {
    switch ($Configuration) {
        "Build" {
            sudo apt-add-repository ppa:lttng/stable-2.10
            sudo apt-get update
            sudo apt-get install -y liblttng-ust-dev
        }
        "Test" {
            sudo apt-add-repository ppa:lttng/stable-2.10
            sudo apt-get update
            sudo apt-get install -y lttng-tools

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

            $NuGetName = "Microsoft.Logging.CLOG2Text.Lttng.0.1.1.nupkg"
            $ToolName = "Microsoft.Logging.CLOG2Text.Lttng"
            $DownloadUrl = "https://github.com/microsoft/CLOG/releases/download/v0.1.1"
            Install-ClogTool -NuGetName $NuGetName -ToolName $ToolName -DownloadUrl $DownloadUrl
        }
        "Dev" {
            sudo apt-add-repository ppa:lttng/stable-2.10
            sudo apt-get update
            sudo apt-get install -y cmake
            sudo apt-get install -y build-essential
            sudo apt-get install -y liblttng-ust-dev
            sudo apt-get install -y lttng-tools
        }
    }
}
