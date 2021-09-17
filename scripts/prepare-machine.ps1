<#

.SYNOPSIS
This script installs all necessary dependencies on the machine, depending
on the provided configuration.

.PARAMETER Configuration
    The type of configuration to install dependencies for.

.PARAMETER InitSubmodules
    Dynamically initializes submodules based Tls and Extra configuration knobs.

.PARAMETER Tls
    The TLS library in use.

.PARAMETER Extra
    Any extra build flags being used.

.PARAMETER Kernel
    Indicates build is for kernel mode.

.PARAMETER TestCertificates
    Generate test certificates. Only supported for Windows test configuration.

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
    [switch]$InitSubmodules,

    [Parameter(Mandatory = $false)]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [string]$Extra = "",

    [Parameter(Mandatory = $false)]
    [switch]$Kernel,

    [Parameter(Mandatory = $false)]
    [switch]$FailOnError,

    [Parameter(Mandatory = $false)]
    [switch]$TestCertificates,

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
$ClogVersion = "0.2.0"
$ClogDownloadUrl = "https://github.com/microsoft/CLOG/releases/download/v$ClogVersion"

$MessagesAtEnd = New-Object Collections.Generic.List[string]

if ($PSVersionTable.PSVersion.Major -lt 7) {

    Write-Error ("`nPowerShell v7.x is needed for this script to work. " +
                 "Please visit https://github.com/microsoft/msquic/blob/main/docs/BUILD.md#powershell-usage")
}

if ($InitSubmodules) {

    # Default TLS based on current platform.
    if ("" -eq $Tls) {
        if ($IsWindows) {
            $Tls = "schannel"
        } else {
            $Tls = "openssl"
        }
    }

    if ($Tls -eq "openssl") {
        Write-Host "Initializing openssl submodule"
        git submodule init submodules/openssl
        git submodule update
    }

    if ($Kernel) {
        # Remove OpenSSL
        git rm submodules/openssl
    }

    if (!$Extra.Contains("-DisableTest")) {
        Write-Host "Initializing googletest submodule"
        git submodule init submodules/googletest
        git submodule update
    }
}

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
        if ($FailOnError) {
            Write-Error $_
        }
        $err = $_
        $MessagesAtEnd.Add("$ToolName could not be installed. Building with logs will not work")
        $MessagesAtEnd.Add($err.ToString())
    }
}

if (($Configuration -eq "Dev")) {
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
            $NasmArch = "win64"
            if (![System.Environment]::Is64BitOperatingSystem) {
                $NasmArch = "win32"
            }
            try {
                Invoke-WebRequest -Uri "https://www.nasm.us/pub/nasm/releasebuilds/$NasmVersion/win64/nasm-$NasmVersion-$NasmArch.zip" -OutFile "build\nasm.zip"
            } catch {
                # Mirror fallback
                Invoke-WebRequest -Uri "https://fossies.org/windows/misc/nasm-$NasmVersion-$NasmArch.zip" -OutFile "build\nasm.zip"
            }
            Expand-Archive -Path "build\nasm.zip" -DestinationPath $env:Programfiles -Force
            $CurrentSystemPath = [Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
            $CurrentSystemPath = "$CurrentSystemPath;$NasmPath"
            $env:PATH = "${env:PATH};$NasmPath"
            [Environment]::SetEnvironmentVariable("PATH", $CurrentSystemPath, [System.EnvironmentVariableTarget]::Machine)
            Write-Host "##vso[task.setvariable variable=PATH;]${env:PATH}"
            Write-Host "PATH has been updated. You'll need to restart your terminal for this to take affect."
        }

        $JomVersion = "1_1_3"
        $JomPath = Join-Path $env:Programfiles "jom_$JomVersion"
        $JomExe = Join-Path $JomPath "jom.exe"
        if (!(Test-Path $JomExe)) {
            New-Item -Path .\build -ItemType Directory -Force
            try {
                Invoke-WebRequest -Uri "https://qt.mirror.constant.com/official_releases/jom/jom_$JomVersion.zip" -OutFile "build\jom.zip"

            } catch {
                Invoke-WebRequest -Uri "https://mirrors.ocf.berkeley.edu/qt/official_releases/jom/jom_$JomVersion.zip" -OutFile "build\jom.zip"
            }
            New-Item -Path $JomPath -ItemType Directory -Force
            Expand-Archive -Path "build\jom.zip" -DestinationPath $JomPath -Force
            $CurrentSystemPath = [Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
            $CurrentSystemPath = "$CurrentSystemPath;$JomPath"
            $env:PATH = "${env:PATH};$JomPath"
            [Environment]::SetEnvironmentVariable("PATH", $CurrentSystemPath, [System.EnvironmentVariableTarget]::Machine)
            Write-Host "##vso[task.setvariable variable=PATH;]${env:PATH}"
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
        if ($TestCertificates) {
            # Install test certificates on windows
            $NewRoot = $false
            Write-Host "Searching for MsQuicTestRoot certificate..."
            $RootCert = Get-ChildItem -path Cert:\LocalMachine\Root\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestRoot"}
            if (!$RootCert) {
                Write-Host "MsQuicTestRoot not found! Creating new MsQuicTestRoot certificate..."
                $RootCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestRoot" -FriendlyName MsQuicTestRoot -KeyUsageProperty Sign -KeyUsage CertSign,DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}ca=1&pathlength=0") -Type Custom
                $TempRootPath = Join-Path $Env:TEMP "MsQuicTestRoot.cer"
                Export-Certificate -Type CERT -Cert $RootCert -FilePath $TempRootPath
                CertUtil.exe -addstore Root $TempRootPath
                Remove-Item $TempRootPath
                $NewRoot = $true
                Write-Host "New MsQuicTestRoot certificate installed!"
            } else {
                Write-Host "Found existing MsQuicTestRoot certificate!"
            }
            Write-Host "Searching for MsQuicTestServer certificate..."
            $ServerCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestServer"}
            if (!$ServerCert) {
                Write-Host "MsQuicTestServer not found! Creating new MsQuicTestServer certificate..."
                $ServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestServer" -DnsName $env:computername,localhost,"127.0.0.1","::1" -FriendlyName MsQuicTestServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert
                $TempServerPath = Join-Path $Env:TEMP "MsQuicTestServerCert.pfx"
                Export-PfxCertificate -Cert $ServerCert -Password $PfxPassword -FilePath $TempServerPath
                Import-PfxCertificate -FilePath $TempServerPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
                Remove-Item $TempServerPath
                Write-Host "New MsQuicTestServer certificate installed!"
            } else {
                Write-Host "Found existing MsQuicTestServer certificate!"
            }
            Write-Host "Searching for MsQuicTestExpiredServer certificate..."
            $ExpiredServerCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestExpiredServer"}
            if (!$ExpiredServerCert) {
                Write-Host "MsQuicTestExpiredServer not found! Creating new MsQuicTestExpiredServer certificate..."
                $ExpiredServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestExpiredServer" -DnsName $env:computername,localhost,"127.0.0.1","::1" -FriendlyName MsQuicTestExpiredServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -NotBefore (Get-Date).AddYears(-2) -NotAfter(Get-Date).AddYears(-1) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert
                $TempExpiredServerPath = Join-Path $Env:TEMP "MsQuicTestExpiredServerCert.pfx"
                Export-PfxCertificate -Cert $ExpiredServerCert -Password $PfxPassword -FilePath $TempExpiredServerPath
                Import-PfxCertificate -FilePath $TempExpiredServerPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
                Remove-Item $TempExpiredServerPath
                Write-Host "New MsQuicTestExpiredServer certificate installed!"
            } else {
                Write-Host "Found existing MsQuicTestExpiredServer certificate!"
            }
            Write-Host "Searching for MsQuicTestClient certificate..."
            $ClientCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestClient"}
            if (!$ClientCert) {
                Write-Host "MsQuicTestClient not found! Creating new MsQuicTestClient certificate..."
                $ClientCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestClient" -FriendlyName MsQuicTestClient -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.2") -Signer $RootCert
                $TempClientPath = Join-Path $Env:TEMP "MsQuicTestClientCert.pfx"
                Export-PfxCertificate -Cert $ClientCert -Password $PfxPassword -FilePath $TempClientPath
                Import-PfxCertificate -FilePath $TempClientPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
                Remove-Item $TempClientPath
                Write-Host "New MsQuicTestClient certificate installed!"
            }else {
                Write-Host "Found existing MsQuicTestClient certificate!"
            }
            Write-Host "Searching for MsQuicTestExpiredClient certificate..."
            $ExpiredClientCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestExpiredClient"}
            if (!$ExpiredClientCert) {
                Write-Host "MsQuicTestExpiredClient not found! Creating new MsQuicTestExpiredClient certificate..."
                $ExpiredClientCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestExpiredClient" -FriendlyName MsQuicTestExpiredClient -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -NotBefore (Get-Date).AddYears(-2) -NotAfter(Get-Date).AddYears(-1) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.2") -Signer $RootCert
                $TempExpiredClientPath = Join-Path $Env:TEMP "MsQuicTestClientExpiredCert.pfx"
                Export-PfxCertificate -Cert $ExpiredClientCert -Password $PfxPassword -FilePath $TempExpiredClientPath
                Import-PfxCertificate -FilePath $TempExpiredClientPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
                Remove-Item $TempExpiredClientPath
                Write-Host "New MsQuicTestExpiredClient certificate installed!"
            }else {
                Write-Host "Found existing MsQuicTestExpiredClient certificate!"
            }
            if ($NewRoot) {
                Write-Host "Deleting MsQuicTestRoot from MY store..."
                Remove-Item $rootCert.PSPath
            }
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

} elseif ($IsLinux) {
    switch ($Configuration) {
        "Build" {
            sudo apt-add-repository ppa:lttng/stable-2.12
            sudo apt-get update
            sudo apt-get install -y liblttng-ust-dev
            # only used for the codecheck CI run:
            sudo apt-get install -y cppcheck clang-tidy
            # used for packaging
            sudo apt-get install -y ruby ruby-dev rpm
            sudo gem install fpm
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
} elseif ($IsMacOS) {
    if ($Configuration -eq "Test") {
        Write-Host "[$(Get-Date)] Setting core dump pattern..."
        sudo sysctl -w kern.corefile=%N.%P.%H.core
    }
}

foreach ($errMsg in $MessagesAtEnd) {
   Write-Warning $errMsg
}
