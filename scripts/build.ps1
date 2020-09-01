<#

.SYNOPSIS
This script provides helpers for building msquic.

.PARAMETER Config
    The debug or release configuration to build for.

.PARAMETER Arch
    The CPU architecture to build for.

.PARAMETER Platform
    Specify which platform to build for

.PARAMETER Tls
    The TLS library to use.

.PARAMETER ToolchainFile
    Toolchain file to use (if cross)

.PARAMETER DisableLogs
    Disables log collection.

.PARAMETER SanitizeAddress
    Enables address sanitizer.

.PARAMETER DisableTools
    Don't build the tools directory.

.PARAMETER DisableTest
    Don't build the test directory.

.PARAMETER DisablePerf
    Don't build the perf directory.

.PARAMETER Clean
    Deletes all previous build and configuration.

.PARAMETER InstallOutput
    Installs the build output to the current machine.

.PARAMETER Parallel
    Enables CMake to build in parallel, where possible.

.PARAMETER DynamicCRT
    Builds msquic with dynamic C runtime (Windows-only).

.PARAMETER PGO
    Builds msquic with profile guided optimization support (Windows-only).

.PARAMETER Generator
    Specifies a specific cmake generator (Only supported on unix)

.PARAMETER SkipPdbAltPath
    Skip setting PDBALTPATH into built binaries on Windows. Without this flag, the PDB must be in the same directory as the DLL or EXE.

.PARAMETER SkipSourceLink
    Skip generating sourcelink and inserting it into the PDB.

.PARAMETER Clang
    Build with Clang if available

.PARAMETER UpdateClog
    Build allowing clog to update the sidecar.

.PARAMETER ConfigureOnly
    Run configuration only.

.PARAMETER CI
    Build is occuring from CI

.EXAMPLE
    build.ps1

.EXAMPLE
    build.ps1 -Config Release

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("uwp", "windows", "linux")] # For future expansion
    [string]$Platform = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [string]$ToolchainFile = "",

    [Parameter(Mandatory = $false)]
    [switch]$DisableLogs = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SanitizeAddress = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTools = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTest = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisablePerf = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Clean = $false,

    [Parameter(Mandatory = $false)]
    [int32]$Parallel = -1,

    [Parameter(Mandatory = $false)]
    [switch]$DynamicCRT = $false,

    [Parameter(Mandatory = $false)]
    [switch]$PGO = $false,

    [Parameter(Mandatory = $false)]
    [string]$Generator = "",

    [Parameter(Mandatory = $false)]
    [switch]$SkipPdbAltPath = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSourceLink = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Clang = $false,

    [Parameter(Mandatory = $false)]
    [switch]$UpdateClog = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ConfigureOnly = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CI = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if ($Generator -eq "") {
    if ($IsWindows) {
        $Generator = "Visual Studio 16 2019"
    } elseif ($IsLinux) {
        $Generator = "Ninja"
    } else {
        $Generator = "Unix Makefiles"
    }
}

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

if ("" -eq $Platform) {
    if ($IsWindows) {
        $Platform = "windows"
    } else {
        $Platform = "linux"
    }
}

if (!$IsWindows -And $Platform -eq "uwp") {
    Write-Error "[$(Get-Date)] Cannot build uwp on non windows platforms"
    exit
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Important directory paths.
$BaseArtifactsDir = Join-Path $RootDir "artifacts"
$BaseBuildDir = Join-Path $RootDir "build"

$ArtifactsDir = Join-Path $BaseArtifactsDir "bin" $Platform
$BuildDir = Join-Path $BaseBuildDir $Platform

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

if ($Clang) {
    if ($IsWindows) {
        Write-Error "Clang is not supported on windows currently"
    }
    $env:CC = 'clang'
    $env:CXX = 'clang++'
}

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
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
        $Arguments += " '$Generator' -A "
        switch ($Arch) {
            "x86"   { $Arguments += "Win32" }
            "x64"   { $Arguments += "x64" }
            "arm"   { $Arguments += "arm" }
            "arm64" { $Arguments += "arm64" }
        }
    } else {
        $Arguments += " '$Generator'"
    }
    $Arguments += " -DQUIC_TLS=" + $Tls
    $Arguments += " -DQUIC_OUTPUT_DIR=" + $ArtifactsDir
    if (!$DisableLogs) {
        $Arguments += " -DQUIC_ENABLE_LOGGING=on"
    }
    if ($SanitizeAddress) {
        $Arguments += " -DQUIC_ENABLE_SANITIZERS=on"
    }
    if ($DisableTools) {
        $Arguments += " -DQUIC_BUILD_TOOLS=off"
    }
    if ($DisableTest) {
        $Arguments += " -DQUIC_BUILD_TEST=off"
    }
    if ($DisablePerf) {
        $Arguments += " -DQUIC_BUILD_PERF=off"
    }
    if ($IsLinux) {
        $Arguments += " -DCMAKE_BUILD_TYPE=" + $Config
    }
    if ($DynamicCRT) {
        $Arguments += " -DQUIC_STATIC_LINK_CRT=off"
    }
    if ($PGO) {
        $Arguments += " -DQUIC_PGO=on"
    }
    if ($Platform -eq "uwp") {
        $Arguments += " -DCMAKE_SYSTEM_NAME=WindowsStore -DCMAKE_SYSTEM_VERSION=10 -DQUIC_UWP_BUILD=on -DQUIC_STATIC_LINK_CRT=Off"
    }
    if ($ToolchainFile -ne "") {
        $Arguments += " ""-DCMAKE_TOOLCHAIN_FILE=" + $ToolchainFile + """"
    }
    if ($SkipPdbAltPath) {
        $Arguments += " -DQUIC_PDBALTPATH=OFF"
    }
    if ($SkipSourceLink) {
        $Arguments += " -DQUIC_SOURCE_LINK=OFF"
    }
    if ($CI) {
        $Arguments += " -DQUIC_CI=ON"
    }
    $Arguments += " ../../.."

    CMake-Execute $Arguments

    if ($PGO -and $Config -eq "Release") {
        # Manually edit project file, since CMake doesn't seem to have a way to do it.
        $FindText = "  <PropertyGroup Label=`"UserMacros`" />"
        $ReplaceText = "  <PropertyGroup Label=`"UserMacros`" />`r`n  <PropertyGroup><LibraryPath>`$(LibraryPath);`$(VC_LibraryPath_VC_$($Arch)_Desktop)</LibraryPath></PropertyGroup>"
        $ProjectFile = Join-Path $BuildDir "src\bin\msquic.vcxproj"
        (Get-Content $ProjectFile) -replace $FindText, $ReplaceText | Out-File $ProjectFile
    }
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
    } else {
        $Arguments += " -- VERBOSE=1"
    }

    CMake-Execute $Arguments

    if ($IsWindows) {
        Copy-Item (Join-Path $BuildDir "obj" $Config "msquic.lib") $ArtifactsDir
        if (!$DisableTools) {
            Copy-Item (Join-Path $BuildDir "obj" $Config "msquicetw.lib") $ArtifactsDir
        }
        if ($PGO -and $Config -eq "Release") {
            Install-Module VSSetup -Scope CurrentUser -Force -SkipPublisherCheck
            $VSInstallationPath = Get-VSSetupInstance | Select-VSSetupInstance -Latest -Require Microsoft.VisualStudio.Component.VC.Tools.x86.x64 | Select-Object -ExpandProperty InstallationPath
            $VCToolVersion = Get-Content -Path "$VSInstallationPath\VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt"
            $VCToolsPath = "$VSInstallationPath\VC\Tools\MSVC\$VCToolVersion\bin\Host$Arch\$Arch"
            if (Test-Path $VCToolsPath) {
                Copy-Item (Join-Path $VCToolsPath "pgort140.dll") $ArtifactsDir
                Copy-Item (Join-Path $VCToolsPath "pgodb140.dll") $ArtifactsDir
                Copy-Item (Join-Path $VCToolsPath "mspdbcore.dll") $ArtifactsDir
                Copy-Item (Join-Path $VCToolsPath "tbbmalloc.dll") $ArtifactsDir
                Copy-Item (Join-Path $VCToolsPath "pgomgr.exe") $ArtifactsDir
            } else {
                Log "Failed to find VC Tools path!"
            }
        }
    }
}

##############################################################
#                     Main Execution                         #
##############################################################

if ($UpdateClog) {
    $env:CLOG_DEVELOPMENT_MODE=1
}

# Generate the build files.
Log "Generating files..."
CMake-Generate

if (!$ConfigureOnly) {
    # Build the code.
    Log "Building..."
    CMake-Build
}

Log "Done."

if ($UpdateClog) {
    $env:CLOG_DEVELOPMENT_MODE=0
}
