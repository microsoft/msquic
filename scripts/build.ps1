<#

.SYNOPSIS
This script provides helpers for building msquic.

.PARAMETER InstallDependencies
    Installs any necessary dependencies.

.PARAMETER InstallAzureDependencies
    Installs any necessary Azure Pipelines dependencies.

.PARAMETER Config
    The debug or release configurationto build for.

.PARAMETER Arch
    The CPU architecture to build for.

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

.PARAMETER Parallel
    Enables CMake to build in parallel, where possible.

.PARAMETER DynamicCRT
    Builds msquic with dynamic C runtime (Windows-only).

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
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "schannel",

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
    [switch]$InstallOutput = $false,

    [Parameter(Mandatory = $false)]
    [int32]$Parallel = -1,

    [Parameter(Mandatory = $false)]
    [switch]$DynamicCRT = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Important directory paths.
$BaseArtifactsDir = Join-Path $RootDir "artifacts"
$BaseBuildDir = Join-Path $RootDir "bld"
$SrcDir = Join-Path $RootDir "src"
$ArtifactsDir = $null
$BuildDir = $null
if ($IsWindows) {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "windows"
    $BuildDir = Join-Path $BaseBuildDir "windows"
} else {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "linux"
    $BuildDir = Join-Path $BaseBuildDir "linux"
}
$ArtifactsDir = Join-Path $ArtifactsDir "$($Arch)_$($Config)_$($Tls)"
$BuildDir = Join-Path $BuildDir "$($Arch)_$($Tls)"

if ($Clean) {
    # Delete old build/config directories.
    if (Test-Path $ArtifactsDir) { Remove-Item $ArtifactsDir -Recurse -Force | Out-Null }
    if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force | Out-Null }
}

# Initialize directories needed for building.
if (!(Test-Path $BaseArtifactsDir)) {
    New-Item -Path $BaseArtifactsDir -ItemType Directory -Force | Out-Null
}
if (!(Test-Path $BuildDir)) { New-Item -Path $BuildDir -ItemType Directory -Force | Out-Null }

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

# Installs just the Azure Pipelines dependencies.
function Install-Azure-Dependencies {
    if ($IsWindows) {
        # TODO - Anything else?
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

# Executes cmake with the given arguments.
function CMake-Execute([String]$Arguments) {
    Log "cmake $($Arguments)"
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
        $Arguments += " 'Visual Studio 16 2019' -A "
        switch ($Arch) {
            "x86"   { $Arguments += "Win32" }
            "x64"   { $Arguments += "x64" }
            "arm"   { $Arguments += "arm" }
            "arm64" { $Arguments += "arm64" }
        }
    } else {
        $Arguments += " 'Linux Makefiles'"
    }
    $Arguments += " -DQUIC_ARCH=" + $Arch
    $Arguments += " -DQUIC_TLS=" + $Tls
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
    if ($IsLinux) {
        $Arguments += " -DCMAKE_BUILD_TYPE=" + $Config
    }
    if ($DynamicCRT) {
        $Arguments += " -DQUIC_STATIC_LINK_CRT=off"
    }
    $Arguments += " ../../.."

    CMake-Execute $Arguments
}

# Uses cmake to generate the build configuration files.
function CMake-Build {
    $Arguments = "--build ."
    if ($Parallel -gt 0) {
        $Arguments += " --parallel $($Parallel)"
    } elseif ($Parallel -eq 0) {
        $Arguments += " --parallel"
    }
    if ($IsWindows) {
        $Arguments += " --config " + $Config
    }

    CMake-Execute $Arguments

    if ($IsWindows) {
        Copy-Item (Join-Path $BuildDir "obj" $Config "msquic.lib") $ArtifactsDir
        if (!$DisableTools) {
            Copy-Item (Join-Path $BuildDir "obj" $Config "msquicetw.lib") $ArtifactsDir
        }
    }
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
