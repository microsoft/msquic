<#

.SYNOPSIS
This script provides helpers for building msquic.

.PARAMETER InstallDependencies
    Installs any necessary dependencies.

.PARAMETER InstallAzureDependencies
    Installs any necessary Azure Pipelines dependencies.

.PARAMETER Config
    The debug or release build configuration to use.

.PARAMETER Tls
    The TLS library to use.

.PARAMETER DisableLogs
    Disables log collection.

.PARAMETER SanitizeAddress
    Enables address sanitizer.

.PARAMETER DisableTools
    Don't build the tools directory.

.PARAMETER DisableTest
    Don't build the test directory.

.PARAMETER Clean
    Deletes all previous build and configuration.

.PARAMETER InstallOutput
    Installs the build output to the current machine.

.EXAMPLE
    build.ps1 -InstallDependencies

.EXAMPLE
    build.ps1

.EXAMPLE
    build.ps1 -Config Release

#>

param (
    [Parameter(Mandatory = $false)]
    [switch]$InstallDependencies = $false,

    [Parameter(Mandatory = $false)]
    [switch]$InstallAzureDependencies = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$DisableLogs = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SanitizeAddress = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTools = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTest = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Clean = $false,

    [Parameter(Mandatory = $false)]
    [switch]$InstallOutput = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Important directory paths.
$BaseArtifactsDir = Join-Path $PSScriptRoot "artifacts"
$BaseBuildDir = Join-Path $PSScriptRoot "bld"
$SrcDir = Join-Path $PSScriptRoot "src"
$ArtifactsDir = $null
$BuildDir = $null
if ($IsWindows) {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "windows"
    $BuildDir = Join-Path $BaseBuildDir "windows"
} else {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "linux"
    $BuildDir = Join-Path $BaseBuildDir "linux"
}

if ($Clean) {
    # Delete old build/config directories.
    if (Test-Path $ArtifactsDir) { Remove-Item $ArtifactsDir -Recurse -Force | Out-Null }
    if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force | Out-Null }
}

# Initialize directories needed for building.
if (!(Test-Path $BaseArtifactsDir)) {
    mkdir $BaseArtifactsDir | Out-Null
    # Build up the artifacts (upload) ignore file.
    ".artifactignore`n*.ilk`n*-results.xml" > (Join-Path $BaseArtifactsDir ".artifactignore")
}
if (!(Test-Path $BaseBuildDir)) { mkdir $BaseBuildDir | Out-Null }
if (!(Test-Path $BuildDir)) { mkdir $BuildDir | Out-Null }

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

# Installs procdump if not already. Windows specific.
function Install-ProcDump {
    if (!(Test-Path bld)) { mkdir bld | Out-Null }
    if (!(Test-Path bld\windows)) { mkdir bld\windows | Out-Null }
    if (!(Test-Path .\bld\windows\procdump)) {
        Log "Installing procdump..."
        # Download the zip file.
        Invoke-WebRequest -Uri https://download.sysinternals.com/files/Procdump.zip -OutFile bld\windows\procdump.zip
        # Extract the zip file.
        Expand-Archive -Path bld\windows\procdump.zip .\bld\windows\procdump
        # Delete the zip file.
        Remove-Item -Path bld\windows\procdump.zip
    }
}

# Installs just the Azure Pipelines dependencies.
function Install-Azure-Dependencies {
    if ($IsWindows) {
        # Enable SChannel TLS 1.3 (client and server).
        $TlsServerKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server"
        # reg.exe add $TlsServerKeyPath /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add $TlsServerKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null
        $TlsClientKeyPath = "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
        # reg.exe add $TlsClientKeyPath /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
        reg.exe add $TlsClientKeyPath /v Enabled /t REG_DWORD /d 1 /f | Out-Null
        # Make sure procdump is installed
        Install-ProcDump
    } else {
        sudo apt-get install liblttng-ust-dev
        sudo apt-get install lttng-tools
    }
}

# Installs all the dependencies.
function Install-Dependencies {
    if ($IsWindows) {
        # TODO - Anything else?
    } else {
        sudo apt-get install cmake
        sudo apt-get install build-essentials
    }
    Install-Azure-Dependencies
}

# Executes msquictext with the given arguments.
function CMake-Execute([String]$Arguments) {
    $process = Start-Process cmake $Arguments -PassThru -NoNewWindow -WorkingDirectory $BuildDir
    $handle = $process.Handle # Magic work around. Don't remove this line.
    $process.WaitForExit();

    if ($process.ExitCode -ne 0) {
        Write-Error "[$(Get-Date)] CMake exited with status code $($process.ExitCode)"
    }
}

# Uses cmake to generate the build configuration files.
function CMake-Generate {
    $Arguments = "-g"
    if ($IsWindows) {
        $Arguments += " 'Visual Studio 16 2019' -A x64"
    } else {
        $Arguments += " 'Linux Makefiles'"
    }
    switch ($Tls) {
        "schannel" { $Arguments += " -DQUIC_TLS=schannel" }
        "openssl"  { $Arguments += " -DQUIC_TLS=openssl" }
        "stub"     { $Arguments += " -DQUIC_TLS=stub" }
        "mitls"    { $Arguments += " -DQUIC_TLS=mitls" }
        ""         { }
    }
    if ($DisableLogs) {
        $Arguments += " -DQUIC_ENABLE_LOGGING=off"
    }
    if ($SanitizeAddress) {
        $Arguments += " -DQUIC_SANITIZE_ADDRESS=on"
    }
    if ($DisableTools) {
        $Arguments += " -DQUIC_BUILD_TOOLS=off"
    }
    if ($DisableTest) {
        $Arguments += " -DQUIC_BUILD_TEST=off"
    }
    $Arguments += " ../.."

    CMake-Execute $Arguments
}

# Uses cmake to generate the build configuration files.
function CMake-Build {
    $Arguments = "--build ."
    switch ($Config) {
        "Debug"    { $Arguments += " --config DEBUG" }
        "Release"  { $Arguments += " --config RELEASE" }
    }

    CMake-Execute $Arguments
}

# Installs all the build output.
function Install-Output {
    if ($IsWindows) {
        # Import the ETW manifest.
        $ManifestDir = Join-Path $SrcDir "manifest"
        $ManifestPath = Join-Path $ManifestDir "MsQuicEtw.man"
        $MsQuicDllPath = Join-Path $ArtifactsDir "bin" $Config "msquic.dll"
        Log "Installing ETW manifest..."
        wevtutil.exe im $ManifestPath /rf:$MsQuicDllPath /mf:$MsQuicDllPath
    } else {
        # TODO - Anything?
    }
}

##############################################################
#                     Main Execution                         #
##############################################################

if ($InstallDependencies) {
    Log "Installing dependencies..."
    Install-Dependencies
} elseif ($InstallAzureDependencies) {
    Log "Installing Azure Pipelines dependencies..."
    Install-Azure-Dependencies
}

# Generate the build files.
Log "Generating files..."
CMake-Generate

# Build the code.
Log "Building..."
CMake-Build

if ($InstallOutput) {
    # Install the build output.
    Install-Output
}

Log "Done."
