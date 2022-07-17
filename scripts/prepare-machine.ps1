<#

.SYNOPSIS
This script installs all necessary dependencies on the machine, depending
on the provided configuration.

.PARAMETER Tls
    The TLS library in use.

.PARAMETER Force
    Overwrite and force installation of all dependencies.

.PARAMETER InitSubmodules
    Dynamically initializes submodules based Tls and Extra configuration knobs.

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
    [switch]$ForOneBranch,

    [Parameter(Mandatory = $false)]
    [switch]$ForOneBranchPackage,

    [Parameter(Mandatory = $false)]
    [switch]$ForBuild,

    [Parameter(Mandatory = $false)]
    [switch]$ForTest,

    [Parameter(Mandatory = $false)]
    [switch]$ForKernel,

    [Parameter(Mandatory = $false)]
    [switch]$InitSubmodules,

    [Parameter(Mandatory = $false)]
    [switch]$InstallSigningCertificate,

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
    [switch]$InstallXdpSdk,

    [Parameter(Mandatory = $false)]
    [switch]$InstallXdpDriver,

    [Parameter(Mandatory = $false)]
    [switch]$UninstallXdp,

    [Parameter(Mandatory = $false)]
    [switch]$InstallClog2Text,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTest
)

# Admin is required because a lot of things are installed to the local machine
# in the script.
#Requires -RunAsAdministrator

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    # This script requires PowerShell core (mostly for xplat stuff).
    Write-Error ("`nPowerShell v7.x or greater is needed for this script to work. " +
                 "Please visit https://github.com/microsoft/msquic/blob/main/docs/BUILD.md#powershell-usage")
}

if (!$ForOneBranch -and !$ForOneBranchPackage -and !$ForBuild -and !$ForTest -and !$InstallXdpDriver -and !$UninstallXdp) {
    # When no args are passed, assume we want to build and test everything
    # locally (i.e. a dev environment). Set Tls to OpenSSL to make sure
    # everything is available.
    Write-Host "No arguments passed, defaulting -ForBuild and -ForTest"
    $ForBuild = $true
    $ForTest = $true
    if ("" -eq $Tls -and !$ForKernel) { $Tls = "openssl" }
}

if ($ForBuild) {
    # When configured for building, make sure we have all possible dependencies
    # enabled for any possible build.
    $InstallNasm = $true
    $InstallJom = $true
    $InstallXdpSdk = $true
    $InitSubmodules = $true
}

if ($ForTest) {
    # When configured for testing, make sure we have all possible dependencies
    # enabled for any possible test.
    $InstallSigningCertificate = $true
    $InstallTestCertificates = $true

    $InstallClog2Text = $true

    #$InstallCodeCoverage = $true # Ideally we'd enable this by default, but it
                                  # hangs sometimes, so we only want to install
                                  # for jobs that absoultely need it.
}

if ($InstallXdpDriver) {
    # The XDP SDK contains XDP driver, so ensure it's downloaded.
    $InstallXdpSdk = $true
}

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) { $Tls = "schannel" }
    else            { $Tls = "openssl" }
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

# Downloads the latest version of XDP (for building).
function Install-Xdp-Sdk {
    if (!$IsWindows) { return } # Windows only
    $XdpPath = Join-Path $ArtifactsPath "xdp"
    if ($Force) {
        try {
            # Make sure an old driver isn't installed.
            netcfg.exe -u ms_xdp
            pnputil.exe /delete-driver "$XdpPath\bin\xdp.inf"
        } catch {}
        rm -Force -Recurse $XdpPath -ErrorAction Ignore | Out-Null
    }
    if (!(Test-Path $XdpPath)) {
        Write-Host "Downloading XDP"
        $ZipPath = Join-Path $ArtifactsPath "xdp.zip"
        Invoke-WebRequest -Uri (Get-Content (Join-Path $PSScriptRoot "xdp-devkit.json") | ConvertFrom-Json).Path -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $XdpPath -Force
        New-Item -Path "$ArtifactsPath\bin\xdp" -ItemType Directory -Force
        Copy-Item -Path "$XdpPath\symbols\*" -Destination "$ArtifactsPath\bin\xdp" -Force
        Copy-Item -Path "$XdpPath\bin\*" -Destination "$ArtifactsPath\bin\xdp" -Force
        Remove-Item -Path $ZipPath
    }
}

# Installs the XDP driver (for testing).
# NB: XDP can be uninstalled via Uninstall-Xdp
function Install-Xdp-Driver {
    if (!$IsWindows) { return } # Windows only
    $XdpPath = Join-Path $ArtifactsPath "xdp"
    if (!(Test-Path $XdpPath)) {
        Write-Error "XDP installation failed: driver file not present"
    }

    Write-Host "Installing XDP certificate"
    try {
        CertUtil.exe -addstore Root "$XdpPath\bin\CoreNetSignRoot.cer"
        CertUtil.exe -addstore TrustedPublisher "$XdpPath\bin\CoreNetSignRoot.cer"
    } catch { }

    Write-Host "Installing XDP driver"
    netcfg.exe -l "$XdpPath\bin\xdp.inf" -c s -i ms_xdp
}

# Completely removes the XDP driver and SDK.
function Uninstall-Xdp {
    if (!$IsWindows) { return } # Windows only
    $XdpPath = Join-Path $ArtifactsPath "xdp"
    if (!(Test-Path $XdpPath)) { return; }

    Write-Host "Uninstalling XDP"
    try { netcfg.exe -u ms_xdp } catch {}
    try { pnputil.exe /delete-driver "$XdpPath\bin\xdp.inf" } catch {}
    rm -Force -Recurse $XdpPath -ErrorAction Ignore | Out-Null
}

# Installs DuoNic from the CoreNet-CI repo.
function Install-DuoNic {
    if (!$IsWindows) { return } # Windows only
    # Check to see if test signing is enabled.
    $HasTestSigning = $false
    try { $HasTestSigning = ("$(bcdedit)" | Select-String -Pattern "testsigning\s+Yes").Matches.Success } catch { }
    if (!$HasTestSigning) { Write-Error "Test Signing Not Enabled!" }

    # Download the CI repo that contains DuoNic.
    Download-CoreNet-Deps

    # Install the test root certificate.
    Write-Host "Installing test root certificate"
    $RootCertPath = Join-Path $SetupPath "testroot-sha2.cer"
    if (!(Test-Path $RootCertPath)) { Write-Error "Missing file: $RootCertPath" }
    certutil.exe -addstore -f "Root" $RootCertPath

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
    $NasmVersion = "2.15.05"
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

# Creates and installs a certificate to use for local signing.
function Install-SigningCertificate {
    if (!$IsWindows -or !(Win-SupportsCerts)) { return } # Windows only
    if (!(Test-Path c:\CodeSign.pfx)) {
        Write-Host "Creating signing certificate"
        $CodeSignCert = New-SelfSignedCertificate -Type Custom -Subject "CN=MsQuicTestCodeSignRoot" -FriendlyName MsQuicTestCodeSignRoot -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -NotAfter(Get-Date).AddYears(1) -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.6","2.5.29.19 = {text}")
        $CodeSignCertPath = Join-Path $Env:TEMP "CodeSignRoot.cer"
        Export-Certificate -Type CERT -Cert $CodeSignCert -FilePath $CodeSignCertPath
        CertUtil.exe -addstore Root $CodeSignCertPath
        Export-PfxCertificate -Cert $CodeSignCert -Password $PfxPassword -FilePath c:\CodeSign.pfx
        Remove-Item $CodeSignCertPath
        Remove-Item $CodeSignCert.PSPath
    }
}

# Creates and installs certificates used for testing.
function Install-TestCertificates {
    if (!$IsWindows -or !(Win-SupportsCerts)) { return } # Windows only
    $DnsNames = $env:computername,"localhost","127.0.0.1","::1","192.168.1.11","192.168.1.12","fc00::1:11","fc00::1:12"
    $NewRoot = $false
    Write-Host "Searching for MsQuicTestRoot certificate..."
    $RootCert = Get-ChildItem -path Cert:\LocalMachine\Root\* -Recurse | Where-Object {$_.Subject -eq "CN=MsQuicTestRoot"}
    if (!$RootCert) {
        Write-Host "MsQuicTestRoot not found! Creating new MsQuicTestRoot certificate..."
        $RootCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestRoot" -FriendlyName MsQuicTestRoot -KeyUsageProperty Sign -KeyUsage CertSign,DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP521 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}ca=1&pathlength=0") -Type Custom
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
        $ServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestServer" -DnsName $DnsNames -FriendlyName MsQuicTestServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert
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
        $ExpiredServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestExpiredServer" -DnsName $DnsNames -FriendlyName MsQuicTestExpiredServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotBefore (Get-Date).AddYears(-2) -NotAfter(Get-Date).AddYears(-1) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert
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
        $ClientCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestClient" -FriendlyName MsQuicTestClient -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.2") -Signer $RootCert
        $TempClientPath = Join-Path $Env:TEMP "MsQuicTestClientCert.pfx"
        Export-PfxCertificate -Cert $ClientCert -Password $PfxPassword -FilePath $TempClientPath
        Import-PfxCertificate -FilePath $TempClientPath -Password $PfxPassword -Exportable -CertStoreLocation Cert:\LocalMachine\My
        Remove-Item $TempClientPath
        Write-Host "New MsQuicTestClient certificate installed!"
    } else {
        Write-Host "Found existing MsQuicTestClient certificate!"
    }

    Write-Host "Searching for MsQuicTestExpiredClient certificate..."
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
        Write-Host "Found existing MsQuicTestExpiredClient certificate!"
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
if ($ForKernel) { git rm submodules/openssl }

if ($InitSubmodules) {

    Write-Host "Initializing clog submodule"
    git submodule init submodules/clog
    git submodule update

    if ($Tls -eq "openssl") {
        Write-Host "Initializing openssl submodule"
        git submodule init submodules/openssl
        git submodule update
    }

    if (!$DisableTest) {
        Write-Host "Initializing googletest submodule"
        git submodule init submodules/googletest
        git submodule update
    }
}

if ($InstallDuoNic) { Install-DuoNic }
if ($InstallXdpSdk) { Install-Xdp-Sdk }
if ($InstallXdpDriver) { Install-Xdp-Driver }
if ($UninstallXdp) { Uninstall-Xdp }
if ($InstallNasm) { Install-NASM }
if ($InstallJOM) { Install-JOM }
if ($InstallCodeCoverage) { Install-OpenCppCoverage }
if ($InstallSigningCertificate) { Install-SigningCertificate }
if ($InstallTestCertificates) { Install-TestCertificates }

if ($IsLinux) {
    if ($InstallClog2Text) {
        Install-Clog2Text
    }

    if ($ForOneBranch) {
        sh -c "wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null"
        sh -c "echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' | sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null"
        $ForBuild = $true
    }

    if ($ForOneBranchPackage) {
        sudo apt-get update
        # used for packaging
        sudo apt-get install -y ruby ruby-dev rpm
        sudo gem install fpm
    }

    if ($ForBuild) {
        sudo apt-add-repository ppa:lttng/stable-2.12
        sudo apt-get update
        sudo apt-get install -y cmake
        sudo apt-get install -y build-essential
        sudo apt-get install -y liblttng-ust-dev
        sudo apt-get install -y libssl-dev
        # only used for the codecheck CI run:
        sudo apt-get install -y cppcheck clang-tidy
        # used for packaging
        sudo apt-get install -y ruby ruby-dev rpm
        sudo gem install fpm
    }

    if ($ForTest) {
        sudo apt-add-repository ppa:lttng/stable-2.12
        sudo apt-get update
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
