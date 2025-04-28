<#

.SYNOPSIS
This script installs all necessary dependencies on the machine, depending
on the provided configuration.

.PARAMETER Tls
    The TLS library in use.

.PARAMETER Force
    Overwrite and force installation of all dependencies.

.PARAMETER ForKernel
    Indicates build is for kernel mode.

.PARAMETER InstallTestCertificates
    Generate test certificates. Only supported on Windows.

.PARAMETER InstallSigningCertificates
    Generate a code signing certificate for kernel driver tests.

.EXAMPLE
    prepare-machine.ps1

.EXAMPLE
    prepare-machine.ps1 -ForBuild

.EXAMPLE
    prepare-machine.ps1 -ForTest

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$ForContainerBuild,

    [Parameter(Mandatory = $false)]
    [switch]$ForBuild,

    [Parameter(Mandatory = $false)]
    [switch]$ForTest,

    [Parameter(Mandatory = $false)]
    [switch]$ForKernel,

    [Parameter(Mandatory = $false)]
    [switch]$InstallSigningCertificates,

    [Parameter(Mandatory = $false)]
    [switch]$InstallTestCertificates,

    [Parameter(Mandatory = $false)]
    [switch]$InstallDuoNic,

    [Parameter(Mandatory = $false)]
    [switch]$InstallCodeCoverage,

    [Parameter(Mandatory = $false)]
    [switch]$InstallNasm,

    [Parameter(Mandatory = $false)]
    [switch]$InstallJom,

    [Parameter(Mandatory = $false)]
    [switch]$UseXdp,

    [Parameter(Mandatory = $false)]
    [switch]$InstallArm64Toolchain,

    [Parameter(Mandatory = $false)]
    [switch]$InstallXdpDriver,

    [Parameter(Mandatory = $false)]
    [switch]$UninstallXdp,

    [Parameter(Mandatory = $false)]
    [switch]$InstallClog2Text,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTest,

    [Parameter(Mandatory = $false)]
    [switch]$InstallCoreNetCiDeps
)

# Admin is required because a lot of things are installed to the local machine
# in the script.
#Requires -RunAsAdministrator

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$PrepConfig = & (Join-Path $PSScriptRoot get-buildconfig.ps1) -Tls $Tls
$Tls = $PrepConfig.Tls

if ($PSVersionTable.PSVersion.Major -lt 7) {
    # This script requires PowerShell core (mostly for xplat stuff).
    Write-Error ("`nPowerShell v7.x or greater is needed for this script to work. " +
                 "Please visit https://github.com/microsoft/msquic/blob/main/docs/BUILD.md#powershell-usage")
}

if (!$ForContainerBuild -and !$ForBuild -and !$ForTest -and !$InstallXdpDriver -and !$UninstallXdp) {
    # When no args are passed, assume we want to build and test everything
    # locally (i.e. a dev environment). Set Tls to OpenSSL to make sure
    # everything is available.
    Write-Host "No arguments passed, defaulting -ForBuild and -ForTest"
    $ForBuild = $true
    $ForTest = $true
}

if ($ForBuild) {
    # When configured for building, make sure we have all possible dependencies
    # enabled for any possible build.
    $InstallNasm = $true
    $InstallJom = $true
    $InstallCoreNetCiDeps = $true; # For kernel signing certs
}

if ($ForTest) {
    # When configured for testing, make sure we have all possible dependencies
    # enabled for any possible test.
    $InstallTestCertificates = $true
    $InstallClog2Text = $true

    # Since installing signing certs also checks whether test signing is enabled, which most
    # likely will fail on a devbox, do it only when we need to test kernel drivers so that
    # local testing setup won't be blocked by test signing not enabled.
    if ($ForKernel) {
        $InstallSigningCertificates = $true;
    }

    if ($UseXdp) {
        $InstallXdpDriver = $true;
        $InstallDuoNic = $true;
    }

    #$InstallCodeCoverage = $true # Ideally we'd enable this by default, but it
                                  # hangs sometimes, so we only want to install
                                  # for jobs that absoultely need it.
}

if ($InstallXdpDriver) {
    $InstallSigningCertificates = $true;
}

if ($InstallDuoNic) {
    $InstallSigningCertificates = $true;
}

if ($InstallSigningCertificates) {
    # Signing certs need the CoreNet-CI dependencies.
    $InstallCoreNetCiDeps = $true;
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$ArtifactsPath = Join-Path $RootDir "artifacts"
if (!(Test-Path $ArtifactsPath)) { mkdir $ArtifactsPath | Out-Null }

# Directory for the corenet CI install.
$CoreNetCiPath = Join-Path $ArtifactsPath "corenet-ci-main"
$SetupPath = Join-Path $CoreNetCiPath "vm-setup"

# Generic, default password for test certificates.
$PfxPassword = ConvertTo-SecureString -String "placeholder" -Force -AsPlainText

# Downloads and caches the latest version of the corenet-ci-main repo.
function Download-CoreNet-Deps {
    if (!$IsWindows) { return } # Windows only
    # Download and extract https://github.com/microsoft/corenet-ci.
    if ($Force) { rm -Force -Recurse $CoreNetCiPath -ErrorAction Ignore }
    if (!(Test-Path $CoreNetCiPath)) {
        Write-Host "Downloading CoreNet-CI"
        $ZipPath = Join-Path $ArtifactsPath "corenet-ci.zip"
        Invoke-WebRequest -Uri "https://github.com/microsoft/corenet-ci/archive/refs/heads/main.zip" -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $ArtifactsPath -Force
        Remove-Item -Path $ZipPath
    }
}

# Installs the certs downloaded via Download-CoreNet-Deps and used for signing
# our test drivers.
function Install-SigningCertificates {
    if (!$IsWindows) { return } # Windows only

    # Check to see if test signing is enabled.
    $HasTestSigning = $false
    try { $HasTestSigning = ("$(bcdedit)" | Select-String -Pattern "testsigning\s+Yes").Matches.Success } catch { }
    if (!$HasTestSigning) { Write-Error "Test Signing Not Enabled!" }

    Write-Host "Installing driver signing certificates"
    try {
        CertUtil.exe -addstore Root "$SetupPath\CoreNetSignRoot.cer" 2>&1 | Out-Null
        CertUtil.exe -addstore TrustedPublisher "$SetupPath\CoreNetSignRoot.cer" 2>&1 | Out-Null
        CertUtil.exe -addstore Root "$SetupPath\testroot-sha2.cer" 2>&1 | Out-Null # For duonic
    } catch {
        Write-Host "WARNING: Exception encountered while installing signing certs. Drivers may not start!"
    }
}

# Installs the XDP driver (for testing).
# NB: XDP can be uninstalled via Uninstall-Xdp
function Install-Xdp-Driver {
    if (!$IsWindows) { return } # Windows only
    Write-Host "Downloading XDP msi"
    $MsiPath = Join-Path $ArtifactsPath "xdp.msi"
    Invoke-WebRequest -Uri (Get-Content (Join-Path $PSScriptRoot "xdp.json") | ConvertFrom-Json).installer -OutFile $MsiPath
    Write-Host "Installing XDP driver"
    msiexec.exe /i $MsiPath /quiet | Out-Null
}

# Completely removes the XDP driver and SDK.
function Uninstall-Xdp {
    if (!$IsWindows) { return } # Windows only
    $MsiPath = Join-Path $ArtifactsPath "xdp.msi"
    if (Test-Path $MsiPath) {
        Write-Host "Uninstalling XDP driver"
        try { msiexec.exe /x $MsiPath /quiet | Out-Null } catch {}
    }
}

# Installs DuoNic from the CoreNet-CI repo.
function Install-DuoNic {
    if (!$IsWindows) { return } # Windows only
    # Install the DuoNic driver.
    Write-Host "Installing DuoNic driver"
    $DuoNicPath = Join-Path $SetupPath duonic
    $DuoNicScript = (Join-Path $DuoNicPath duonic.ps1)
    if (!(Test-Path $DuoNicScript)) { Write-Error "Missing file: $DuoNicScript" }
    Invoke-Expression "cmd /c `"pushd $DuoNicPath && pwsh duonic.ps1 -Install`""
}

function Update-Path($NewPath) {
    Write-Host "Updating PATH"
    $CurrentSystemPath = [Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)
    $CurrentSystemPath = "$CurrentSystemPath;$NewPath"
    $env:PATH = "${env:PATH};$NewPath"
    [Environment]::SetEnvironmentVariable("PATH", $CurrentSystemPath, [System.EnvironmentVariableTarget]::Machine)
    Write-Host "##vso[task.setvariable variable=PATH;]${env:PATH}"
    Write-Host "PATH has been updated. You'll need to restart your terminal for this to take affect."
}

# Installs NASM from the public release.
function Install-NASM {
    if (!$IsWindows) { return } # Windows only
    $NasmVersion = "2.16.01"
    $NasmPath = Join-Path $env:Programfiles "nasm-$NasmVersion"
    $NasmExe = Join-Path $NasmPath "nasm.exe"
    if ($Force) { rm -Force -Recurse $NasmPath -ErrorAction Ignore }
    if (!(Test-Path $NasmExe) -and $env:GITHUB_PATH -eq $null) {
        Write-Host "Downloading NASM"
        $NasmArch = "win64"
        if (![System.Environment]::Is64BitOperatingSystem) { $NasmArch = "win32" }
        try {
            Invoke-WebRequest -Uri "https://www.nasm.us/pub/nasm/releasebuilds/$NasmVersion/win64/nasm-$NasmVersion-$NasmArch.zip" -OutFile "artifacts\nasm.zip"
        } catch {
            # Mirror fallback
            Invoke-WebRequest -Uri "https://fossies.org/windows/misc/nasm-$NasmVersion-$NasmArch.zip" -OutFile "artifacts\nasm.zip"
        }

        Write-Host "Extracting/installing NASM"
        Expand-Archive -Path "artifacts\nasm.zip" -DestinationPath $env:Programfiles -Force
        Remove-Item -Path "artifacts\nasm.zip"
        Update-Path $NasmPath
    }
}

# Installs JOM from the public release.
function Install-JOM {
    if (!$IsWindows) { return } # Windows only
    $JomVersion = "1_1_3"
    $JomPath = Join-Path $env:Programfiles "jom_$JomVersion"
    $JomExe = Join-Path $JomPath "jom.exe"
    if (!(Test-Path $JomExe) -and $env:GITHUB_PATH -eq $null) {
        Write-Host "Downloading JOM"
        try {
            Invoke-WebRequest -Uri "https://qt.mirror.constant.com/official_releases/jom/jom_$JomVersion.zip" -OutFile "artifacts\jom.zip"
        } catch {
            # Mirror fallback
            Invoke-WebRequest -Uri "https://mirrors.ocf.berkeley.edu/qt/official_releases/jom/jom_$JomVersion.zip" -OutFile "artifacts\jom.zip"
        }

        Write-Host "Extracting/installing JOM"
        New-Item -Path $JomPath -ItemType Directory -Force
        Expand-Archive -Path "artifacts\jom.zip" -DestinationPath $JomPath -Force
        Remove-Item -Path "artifacts\jom.zip"
        Update-Path $JomPath
    }
}

# Installs OpenCppCoverage from the public release.
function Install-OpenCppCoverage {
    if (!$IsWindows) { return } # Windows only
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
        Remove-Item -Path $ExeFile
    }
}

# Checks the OS version number to see if it's recent enough (> 2019) to support
# the necessary features for creating and installing the test certificates.
function Win-SupportsCerts {
    $ver = [environment]::OSVersion.Version
    if ($ver.Build -lt 20000) { return $false }
    return $true
}

# Creates and installs certificates used for testing.
function Install-TestCertificates {
    if (!$IsWindows -or !(Win-SupportsCerts)) { return } # Windows only
    $DnsNames = $env:computername,"localhost","127.0.0.1","::1","192.168.1.11","192.168.1.12","fc00::1:11","fc00::1:12"
    $NewRoot = $false
    Write-Debug "Searching for MsQuicTestRoot certificate..."
    $RootCert = Get-ChildItem -path Cert:\LocalMachine\Root\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestRoot"}
    if (!$RootCert) {
        Write-Host "MsQuicTestRoot not found! Creating new MsQuicTestRoot certificate..."
        $RootCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestRoot" -FriendlyName MsQuicTestRoot -KeyUsageProperty Sign -KeyUsage CertSign,DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP521 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}ca=1&pathlength=0") -Type Custom
        $TempRootPath = Join-Path $Env:TEMP "MsQuicTestRoot.cer"
        Export-Certificate -Type CERT -Cert $RootCert -FilePath $TempRootPath
        CertUtil.exe -addstore Root $TempRootPath 2>&1 | Out-Null
        Remove-Item $TempRootPath
        $NewRoot = $true
        Write-Host "New MsQuicTestRoot certificate installed!"
    } else {
        Write-Debug "Found existing MsQuicTestRoot certificate!"
    }

    Write-Debug "Searching for MsQuicTestServer certificate..."
    $ServerCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestServer"}
    if (!$ServerCert) {
        Write-Host "MsQuicTestServer not found! Creating new MsQuicTestServer certificate..."
        $ServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestServer" -DnsName $DnsNames -FriendlyName MsQuicTestServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert
        $TempServerPath = Join-Path $Env:TEMP "MsQuicTestServerCert.pfx"
        Export-PfxCertificate -Cert $ServerCert -Password $PfxPassword -FilePath $TempServerPath
        Import-PfxCertificate -FilePath $TempServerPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
        Remove-Item $TempServerPath
        Write-Host "New MsQuicTestServer certificate installed!"
    } else {
        Write-Debug "Found existing MsQuicTestServer certificate!"
    }

    Write-Debug "Searching for MsQuicTestExpiredServer certificate..."
    $ExpiredServerCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestExpiredServer"}
    if (!$ExpiredServerCert) {
        Write-Host "MsQuicTestExpiredServer not found! Creating new MsQuicTestExpiredServer certificate..."
        $ExpiredServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestExpiredServer" -DnsName $DnsNames -FriendlyName MsQuicTestExpiredServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotBefore (Get-Date).AddYears(-2) -NotAfter(Get-Date).AddYears(-1) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert
        $TempExpiredServerPath = Join-Path $Env:TEMP "MsQuicTestExpiredServerCert.pfx"
        Export-PfxCertificate -Cert $ExpiredServerCert -Password $PfxPassword -FilePath $TempExpiredServerPath
        Import-PfxCertificate -FilePath $TempExpiredServerPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
        Remove-Item $TempExpiredServerPath
        Write-Host "New MsQuicTestExpiredServer certificate installed!"
    } else {
        Write-Debug "Found existing MsQuicTestExpiredServer certificate!"
    }

    Write-Debug "Searching for MsQuicTestClient certificate..."
    $ClientCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestClient"}
    if (!$ClientCert) {
        Write-Host "MsQuicTestClient not found! Creating new MsQuicTestClient certificate..."
        $ClientCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestClient" -FriendlyName MsQuicTestClient -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.2") -Signer $RootCert
        $TempClientPath = Join-Path $Env:TEMP "MsQuicTestClientCert.pfx"
        Export-PfxCertificate -Cert $ClientCert -Password $PfxPassword -FilePath $TempClientPath
        Import-PfxCertificate -FilePath $TempClientPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
        Remove-Item $TempClientPath
        Write-Host "New MsQuicTestClient certificate installed!"
    } else {
        Write-Debug "Found existing MsQuicTestClient certificate!"
    }

    Write-Debug "Searching for MsQuicTestExpiredClient certificate..."
    $ExpiredClientCert = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestExpiredClient"}
    if (!$ExpiredClientCert) {
        Write-Host "MsQuicTestExpiredClient not found! Creating new MsQuicTestExpiredClient certificate..."
        $ExpiredClientCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestExpiredClient" -FriendlyName MsQuicTestExpiredClient -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotBefore (Get-Date).AddYears(-2) -NotAfter(Get-Date).AddYears(-1) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.2") -Signer $RootCert
        $TempExpiredClientPath = Join-Path $Env:TEMP "MsQuicTestClientExpiredCert.pfx"
        Export-PfxCertificate -Cert $ExpiredClientCert -Password $PfxPassword -FilePath $TempExpiredClientPath
        Import-PfxCertificate -FilePath $TempExpiredClientPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
        Remove-Item $TempExpiredClientPath
        Write-Host "New MsQuicTestExpiredClient certificate installed!"
    } else {
        Write-Debug "Found existing MsQuicTestExpiredClient certificate!"
    }

    if ($NewRoot) {
        Write-Host "Deleting MsQuicTestRoot from MY store..."
        Remove-Item $rootCert.PSPath
    }
}

function Install-DotnetTool {
    param($ToolName, $Version, $NuGetPath)
    $NuGetName = "$ToolName.$Version.nupkg"
    $NuGetFile = Join-Path $NuGetPath $NuGetName
    if (!(Test-Path -Path $NuGetFile)) {
        Write-Host "$ToolName not found. Parsing lttng logs will fail"
        return
    }

    try {
        Write-Host "Installing: $ToolName"
        dotnet tool update --global --add-source $NuGetPath $ToolName
    } catch {
        $err = $_
        Write-Host "$ToolName could not be installed. Parsing lttng logs will fail"
        Write-Host $err.ToString()
    }
}

function Install-Clog2Text {
    Write-Host "Initializing clog submodule"
    git submodule init submodules/clog
    git submodule update

    dotnet build (Join-Path $RootDir submodules clog)
    $NuGetPath = Join-Path $RootDir "submodules" "clog" "src" "nupkg"
    Install-DotnetTool -ToolName "Microsoft.Logging.CLOG2Text.Lttng" -Version "0.0.1" -NuGetPath $NuGetPath
}

# We remove OpenSSL path for kernel builds because it's not needed.
if ($ForKernel) {
    git rm submodules/openssl
    git rm submodules/openssl3
}

if ($ForBuild -or $ForContainerBuild) {

    Write-Host "Initializing clog submodule"
    git submodule init submodules/clog

    if (!$IsLinux) {
        Write-Host "Initializing XDP-for-Windows submodule"
        git submodule init submodules/xdp-for-windows
    }

    if ($Tls -eq "openssl") {
        Write-Host "Initializing openssl submodule"
        git submodule init submodules/openssl
    }

    if ($Tls -eq "openssl3") {
        Write-Host "Initializing openssl3 submodule"
        git submodule init submodules/openssl3
    }

    if (!$DisableTest) {
        Write-Host "Initializing googletest submodule"
        git submodule init submodules/googletest
    }

    git submodule update --jobs=8
}

if ($InstallCoreNetCiDeps) { Download-CoreNet-Deps }
if ($InstallSigningCertificates) { Install-SigningCertificates }
if ($InstallDuoNic) { Install-DuoNic }
if ($InstallXdpDriver) { Install-Xdp-Driver }
if ($UninstallXdp) { Uninstall-Xdp }
if ($InstallNasm) { Install-NASM }
if ($InstallJOM) { Install-JOM }
if ($InstallCodeCoverage) { Install-OpenCppCoverage }
if ($InstallTestCertificates) { Install-TestCertificates }

if ($IsLinux) {
    if ($InstallClog2Text) {
        Install-Clog2Text
    }

    if ($ForBuild) {
        sudo apt-add-repository ppa:lttng/stable-2.13 -y
        sudo apt-get update -y
        sudo apt-get install -y cmake
        sudo apt-get install -y build-essential
        sudo apt-get install -y liblttng-ust-dev
        sudo apt-get install -y libssl-dev
        sudo apt-get install -y libnuma-dev
        if ($InstallArm64Toolchain) {
            sudo apt-get install -y gcc-aarch64-linux-gnu
            sudo apt-get install -y binutils-aarch64-linux-gnu
            sudo apt-get install -y g++-aarch64-linux-gnu
        }
        # only used for the codecheck CI run:
        sudo apt-get install -y cppcheck clang-tidy
        # used for packaging
        sudo apt-get install -y ruby ruby-dev rpm
        sudo gem install public_suffix -v 4.0.7
        sudo gem install fpm
    }

    if ($ForTest) {
        sudo apt-add-repository ppa:lttng/stable-2.13 -y
        sudo apt-get update -y
        sudo apt-get install -y lttng-tools
        sudo apt-get install -y liblttng-ust-dev
        sudo apt-get install -y gdb

        # Enable core dumps for the system.
        Write-Host "Setting core dump size limit"
        sudo sh -c "echo 'root soft core unlimited' >> /etc/security/limits.conf"
        sudo sh -c "echo 'root hard core unlimited' >> /etc/security/limits.conf"
        sudo sh -c "echo '* soft core unlimited' >> /etc/security/limits.conf"
        sudo sh -c "echo '* hard core unlimited' >> /etc/security/limits.conf"
        #sudo cat /etc/security/limits.conf

        # Set the core dump pattern.
        Write-Host "Setting core dump pattern"
        sudo sh -c "echo -n '%e.%p.%t.core' > /proc/sys/kernel/core_pattern"
        #sudo cat /proc/sys/kernel/core_pattern
    }
}

if ($IsMacOS) {
    if ($ForTest) {
        Write-Host "Setting core dump pattern"
        sudo sysctl -w kern.corefile=%N.%P.core
    }
}
