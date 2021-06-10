<#

.SYNOPSIS
This script installs all necessary dependencies on the machine, depending
on the provided configuration.

.PARAMETER Configuration
    The type of configuration to install dependencies for.

.PARAMETER SignCode
    Generate a code signing certificate for kernel driver tests.

.EXAMPLE
    prepare-machine.ps1 -Configuration Build

.EXAMPLE
    prepare-machine.ps1 -Configuration Test

#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Build", "Test", "Dev")]
    [string]$Configuration,

    [Parameter(Mandatory = $false)]
    [switch]$SignCode
)

#Requires -RunAsAdministrator

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$NuGetPath = Join-Path $RootDir "nuget"

# Well-known location for clog packages.
$ClogVersion = "0.1.9"
$ClogDownloadUrl = "https://github.com/microsoft/CLOG/releases/download/v$ClogVersion"

$MessagesAtEnd = New-Object Collections.Generic.List[string]

function Install-ClogTool {
    param($ToolName)
    New-Item -Path $NuGetPath -ItemType Directory -Force | Out-Null
    $NuGetName = "$ToolName.$ClogVersion.nupkg"
    $NuGetFile = Join-Path $NuGetPath $NuGetName
    try {
        if (!(Test-Path $NuGetFile)) {
            Write-Host "Downloading $ClogDownloadUrl/$NuGetName"
            Invoke-WebRequest -Uri "$ClogDownloadUrl/$NuGetName" -OutFile $NuGetFile
        }
        Write-Host "Installing: $NuGetName"
        dotnet tool update --global --add-source $NuGetPath $ToolName
    } catch {
        $err = $_
        $MessagesAtEnd.Add("$ToolName could not be installed. Building with logs will not work")
        $MessagesAtEnd.Add($err.ToString())
    }
}

if (($Configuration -eq "Dev") -or ($Configuration -eq "Build")) {
    Install-ClogTool "Microsoft.Logging.CLOG"
}

if ($IsWindows) {

    if ($Configuration -eq "Dev") {
        # TODO - Support installing VS and necessary addins
        # TODO - Install CMake
        # TODO - Check for Windows preview
    }

    if (($Configuration -eq "Dev") -or ($Configuration -eq "Build")) {
        $NasmVersion = "2.15.05"
        $NasmPath = Join-Path $env:Programfiles "nasm-$NasmVersion"
        $NasmExe = Join-Path $NasmPath "nasm.exe"
        if (!(Test-Path $NasmExe)) {
            New-Item -Path .\build -ItemType Directory -Force
            if ([System.Environment]::Is64BitOperatingSystem) {
                Invoke-WebRequest -Uri "https://www.nasm.us/pub/nasm/releasebuilds/$NasmVersion/win64/nasm-$NasmVersion-win64.zip" -OutFile "build\nasm.zip"
            } else {
                Invoke-WebRequest -Uri "https://www.nasm.us/pub/nasm/releasebuilds/$NasmVersion/win32/nasm-$NasmVersion-win32.zip" -OutFile "build\nasm.zip"
            }
            Expand-Archive -Path "build\nasm.zip" -DestinationPath $env:Programfiles -Force
            $CurrentSystemPath = [Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
            $CurrentSystemPath = "$CurrentSystemPath;$NasmPath"
            [Environment]::SetEnvironmentVariable("PATH", $CurrentSystemPath, [System.EnvironmentVariableTarget]::Machine)
            Write-Host "##vso[task.setvariable variable=PATH;]${env:PATH};$NasmPath"
            Write-Host "PATH has been updated. You'll need to restart your terminal for this to take affect."
        }
    }

    if (($Configuration -eq "Dev") -or ($Configuration -eq "Test")) {
        Install-ClogTool "Microsoft.Logging.CLOG2Text.Windows"
    }

    if ($Configuration -eq "Test") {
        $PfxPassword = ConvertTo-SecureString -String "placeholder" -Force -AsPlainText
        if ($SignCode -and !(Test-Path c:\CodeSign.pfx)) {
            $CodeSignCert = New-SelfSignedCertificate -Type Custom -Subject "CN=MsQuicTestCodeSignRoot" -FriendlyName MsQuicTestCodeSignRoot -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -NotAfter(Get-Date).AddYears(1) -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.6","2.5.29.19 = {text}")
            $CodeSignCertPath = Join-Path $Env:TEMP "CodeSignRoot.cer"
            Export-Certificate -Type CERT -Cert $CodeSignCert -FilePath $CodeSignCertPath
            CertUtil.exe -addstore Root $CodeSignCertPath
            Export-PfxCertificate -Cert $CodeSignCert -Password $PfxPassword -FilePath c:\CodeSign.pfx
            Remove-Item $CodeSignCertPath
            Remove-Item $CodeSignCert.PSPath
        }
        # Install OpenCppCoverage on test machines
        if (!(Test-Path "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe")) {
            # Download the installer.
            $Installer = $null
            if ([System.Environment]::Is64BitOperatingSystem) {
                $Installer = "OpenCppCoverageSetup-x64-0.9.9.0.exe"
            } else {
                $Installer = "OpenCppCoverageSetup-x86-0.9.9.0.exe"
            }
            $ExeFile = Join-Path $Env:TEMP $Installer
            Write-Host "Downloading $Installer"
            Invoke-WebRequest -Uri "https://github.com/OpenCppCoverage/OpenCppCoverage/releases/download/release-0.9.9.0/$($Installer)" -OutFile $ExeFile

            # Start the installer and wait for it to finish.
            Write-Host "Installing $Installer"
            Start-Process $ExeFile -Wait -ArgumentList {"/silent"} -NoNewWindow

            # Delete the installer.
            Remove-Item -Path $ExeFile
        }
    }

} else {
    switch ($Configuration) {
        "Build" {
            sudo apt-add-repository ppa:lttng/stable-2.12
            sudo apt-get update
            sudo apt-get install -y liblttng-ust-dev
        }
        "Test" {
            sudo apt-add-repository ppa:lttng/stable-2.12
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

            Install-ClogTool "Microsoft.Logging.CLOG2Text.Lttng"
        }
        "Dev" {
            sudo apt-add-repository ppa:lttng/stable-2.12
            sudo apt-get update
            sudo apt-get install -y cmake
            sudo apt-get install -y build-essential
            sudo apt-get install -y liblttng-ust-dev
            sudo apt-get install -y lttng-tools

            Install-ClogTool "Microsoft.Logging.CLOG2Text.Lttng"
        }
    }
}

foreach ($errMsg in $MessagesAtEnd) {
   Write-Warning $errMsg
}
