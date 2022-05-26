<#

.SYNOPSIS
This script provides helpers for building msquic.

.PARAMETER Config
    The debug or release configuration to build for.

.PARAMETER Arch
    The CPU architecture to build for.

.PARAMETER Platform
    Specify which platform to build for.

.PARAMETER Static
    Specify a static library is preferred (shared is the default).

.PARAMETER Tls
    The TLS library to use.

.PARAMETER ToolchainFile
    Toolchain file to use (if cross).

.PARAMETER DisableLogs
    Disables log collection.

.PARAMETER SanitizeAddress
    Enables address sanitizer.

.PARAMETER CodeCheck
    Enables static code checkers.

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

.PARAMETER EnableTelemetryAsserts
    Enables telemetry asserts in release builds.

.PARAMETER UseSystemOpenSSLCrypto
    Use system provided OpenSSL libcrypto rather then statically linked. Only affects OpenSSL Linux builds

.PARAMETER EnableHighResolutionTimers
    Configures the system to use high resolution timers.

.PARAMETER SharedEC
    Uses shared execution contexts (threads) where possible.

.PARAMETER UseXdp
    Use XDP for the datapath instead of system socket APIs.

.PARAMETER ExtraArtifactDir
    Add an extra classifier to the artifact directory to allow publishing alternate builds of same base library

.PARAMETER LibraryName
    Renames the library to whatever is passed in

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
    [ValidateSet("x86", "x64", "arm", "arm64", "arm64ec")]
    [string]$Arch = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("gamecore_console", "uwp", "windows", "linux", "macos", "android", "ios")] # For future expansion
    [string]$Platform = "",

    [Parameter(Mandatory = $false)]
    [switch]$Static = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [string]$ToolchainFile = "",

    [Parameter(Mandatory = $false)]
    [switch]$DisableLogs = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SanitizeAddress = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CodeCheck = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTools = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisableTest = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DisablePerf = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Clean = $false,

    [Parameter(Mandatory = $false)]
    [int32]$Parallel = -2,

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
    [switch]$CI = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableTelemetryAsserts = $false,

    [Parameter(Mandatory = $false)]
    [switch]$UseSystemOpenSSLCrypto = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableHighResolutionTimers = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SharedEC = $false,

    [Parameter(Mandatory = $false)]
    [switch]$UseXdp = $false,

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = "",

    [Parameter(Mandatory = $false)]
    [string]$LibraryName = "msquic"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if ($Parallel -lt -1) {
    if ($IsWindows) {
        $Parallel = -1
    } else {
        $Parallel = 0
    }
}

$BuildConfig = & (Join-Path $PSScriptRoot get-buildconfig.ps1) -Platform $Platform -Tls $Tls -Arch $Arch -ExtraArtifactDir $ExtraArtifactDir -Config $Config

$Platform = $BuildConfig.Platform
$Tls = $BuildConfig.Tls
$Arch = $BuildConfig.Arch
$ArtifactsDir = $BuildConfig.ArtifactsDir

if ($Generator -eq "") {
    if (!$IsWindows) {
        $Generator = "Unix Makefiles"
    }
}

if (!$IsWindows -And $Platform -eq "uwp") {
    Write-Error "[$(Get-Date)] Cannot build uwp on non windows platforms"
    exit
}

if (!$IsWindows -And ($Platform -eq "gamecore_console")) {
    Write-Error "[$(Get-Date)] Cannot build gamecore on non windows platforms"
    exit
}

if ($Arch -ne "x64" -And ($Platform -eq "gamecore_console")) {
    Write-Error "[$(Get-Date)] Cannot build gamecore for non-x64 platforms"
    exit
}

if ($Arch -eq "arm64ec") {
    if (!$IsWindows) {
        Write-Error "Arm64EC is only supported on Windows"
    }
    if ($Tls -eq "openssl") {
        Write-Error "Arm64EC does not support openssl"
    }
}

if ($Platform -eq "ios" -and !$Static) {
    $Static = $true
    Write-Host "iOS can only be built as static"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Important directory paths.
$BaseArtifactsDir = Join-Path $RootDir "artifacts"
$BaseBuildDir = Join-Path $RootDir "build"

$BuildDir = Join-Path $BaseBuildDir $Platform
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
    $Arguments = ""

    if ($Generator.Contains(" ")) {
        $Generator = """$Generator"""
    }

    if ($IsWindows) {
        if ($Generator.Contains("Visual Studio") -or [string]::IsNullOrWhiteSpace($Generator)) {
            if ($Generator.Contains("Visual Studio")) {
                $Arguments += " -G $Generator"
            }
            $Arguments += " -A "
            switch ($Arch) {
                "x86"   { $Arguments += "Win32" }
                "x64"   { $Arguments += "x64" }
                "arm"   { $Arguments += "arm" }
                "arm64" { $Arguments += "arm64" }
                "arm64ec" { $Arguments += "arm64ec" }
            }
        } else {
            Write-Host "Non VS based generators must be run from a Visual Studio Developer Powershell Prompt matching the passed in architecture"
            $Arguments += " -G $Generator"
        }
    } else {
        $Arguments += "-G $Generator"
    }
    if ($Platform -eq "ios") {
        $IosTCFile = Join-Path $RootDir cmake toolchains ios.cmake
        $Arguments +=  " -DCMAKE_TOOLCHAIN_FILE=""$IosTCFile"" -DDEPLOYMENT_TARGET=""13.0"" -DENABLE_ARC=0 -DCMAKE_OSX_DEPLOYMENT_TARGET=""13.0"""
        switch ($Arch) {
            "x64"   { $Arguments += " -DPLATFORM=SIMULATOR64"}
            "arm64" { $Arguments += " -DPLATFORM=OS64"}
        }
    }
    if ($Platform -eq "macos") {
        switch ($Arch) {
            "x64"   { $Arguments += " -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_OSX_DEPLOYMENT_TARGET=""10.15"""}
            "arm64" { $Arguments += " -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=""11.0"""}
        }
    }
    if($Static) {
        $Arguments += " -DQUIC_BUILD_SHARED=off"
    }
    $Arguments += " -DQUIC_TLS=" + $Tls
    $Arguments += " -DQUIC_OUTPUT_DIR=""$ArtifactsDir"""

    if ($IsLinux) {
        $Arguments += " -DQUIC_LINUX_LOG_ENCODER=lttng"
    }
    if (!$DisableLogs) {
        $Arguments += " -DQUIC_ENABLE_LOGGING=on"
    }
    if ($SanitizeAddress) {
        $Arguments += " -DQUIC_ENABLE_SANITIZERS=on"
    }
    if ($CodeCheck) {
        $Arguments += " -DQUIC_CODE_CHECK=on"
    }
    if ($Platform -ne "uwp" -and $Platform -ne "gamecore_console") {
        if (!$DisableTools) {
            $Arguments += " -DQUIC_BUILD_TOOLS=on"
        }
        if (!$DisableTest) {
            $Arguments += " -DQUIC_BUILD_TEST=on"
        }
        if (!$DisablePerf) {
            $Arguments += " -DQUIC_BUILD_PERF=on"
        }
    }
    if (!$IsWindows) {
        $ConfigToBuild = $Config;
        if ($Config -eq "Release") {
            $ConfigToBuild = "RelWithDebInfo"
        }
        $Arguments += " -DCMAKE_BUILD_TYPE=" + $ConfigToBuild
    }
    if ($DynamicCRT) {
        $Arguments += " -DQUIC_STATIC_LINK_CRT=off"
    }
    if ($PGO) {
        $Arguments += " -DQUIC_PGO=on"
    }
    if ($Platform -eq "uwp") {
        $Arguments += " -DCMAKE_SYSTEM_NAME=WindowsStore -DCMAKE_SYSTEM_VERSION=10 -DQUIC_UWP_BUILD=on"
    }
    if ($Platform -eq "gamecore_console") {
        $Arguments += " -DQUIC_GAMECORE_BUILD=on"
    }
    if ($ToolchainFile -ne "") {
        $Arguments += " -DCMAKE_TOOLCHAIN_FILE=""$ToolchainFile"""
    }
    if ($SkipPdbAltPath) {
        $Arguments += " -DQUIC_PDBALTPATH=OFF"
    }
    if ($SkipSourceLink) {
        $Arguments += " -DQUIC_SOURCE_LINK=OFF"
    }
    if ($CI) {
        $Arguments += " -DQUIC_CI=ON"
        if ($Platform -eq "android" -or $ToolchainFile -ne "") {
            $Arguments += " -DQUIC_SKIP_CI_CHECKS=ON"
        }
        $Arguments += " -DQUIC_VER_BUILD_ID=$env:BUILD_BUILDID"
        $Arguments += " -DQUIC_VER_SUFFIX=-official"
    }
    if ($EnableTelemetryAsserts) {
        $Arguments += " -DQUIC_TELEMETRY_ASSERTS=on"
    }
    if ($UseSystemOpenSSLCrypto) {
        $Arguments += " -DQUIC_USE_SYSTEM_LIBCRYPTO=on"
    }
    if ($EnableHighResolutionTimers) {
        $Arguments += " -DQUIC_HIGH_RES_TIMERS=on"
    }
    if ($SharedEC) {
        $Arguments += " -DQUIC_SHARED_EC=on"
    }
    if ($UseXdp) {
        $Arguments += " -DQUIC_USE_XDP=on"
    }
    if ($Platform -eq "android") {
        $env:PATH = "$env:ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$env:PATH"
        switch ($Arch) {
            "x86"   { $Arguments += " -DANDROID_ABI=x86"}
            "x64"   { $Arguments += " -DANDROID_ABI=x86_64" }
            "arm"   { $Arguments += " -DANDROID_ABI=armeabi-v7a" }
            "arm64" { $Arguments += " -DANDROID_ABI=arm64-v8a" }
        }
        $Arguments += " -DANDROID_PLATFORM=android-29"
        $NDK = $env:ANDROID_NDK_HOME
        $NdkToolchainFile = "$NDK/build/cmake/android.toolchain.cmake"
        $Arguments += " -DANDROID_NDK=""$NDK"""
        $Arguments += " -DCMAKE_TOOLCHAIN_FILE=""$NdkToolchainFile"""
    }
    $Arguments += " -DQUIC_LIBRARY_NAME=$LibraryName"
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
    } else {
        $Arguments += " -- VERBOSE=1"
    }

    CMake-Execute $Arguments

    if ($IsWindows) {
        Copy-Item (Join-Path $BuildDir "obj" $Config "$LibraryName.lib") $ArtifactsDir
        if ($SanitizeAddress -or ($PGO -and $Config -eq "Release")) {
            $CacheFile = Join-Path $BuildDir "CMakeCache.txt"
            $LinkerMatches = Select-String -Path $CacheFile -Pattern "CMAKE_LINKER:FILEPATH=(.+)"
            if ($LinkerMatches.Matches.Length -eq 1 -and $LinkerMatches.Matches[0].Groups.Count -eq 2) {
                $Linker = $LinkerMatches.Matches[0].Groups[1].Value
                $VCToolsPath = Split-Path -Path $Linker -Parent
                if ($PGO) {
                    Copy-Item (Join-Path $VCToolsPath "pgort140.dll") $ArtifactsDir
                    Copy-Item (Join-Path $VCToolsPath "pgodb140.dll") $ArtifactsDir
                    Copy-Item (Join-Path $VCToolsPath "mspdbcore.dll") $ArtifactsDir
                    Copy-Item (Join-Path $VCToolsPath "tbbmalloc.dll") $ArtifactsDir
                    Copy-Item (Join-Path $VCToolsPath "pgomgr.exe") $ArtifactsDir
                }
                if ($SanitizeAddress) {
                    Copy-Item (Join-Path $VCToolsPath "clang_rt.asan_dbg_dynamic-x86_64.dll") $ArtifactsDir
                    Copy-Item (Join-Path $VCToolsPath "clang_rt.asan_dynamic-x86_64.dll") $ArtifactsDir
                }
            } else {
                Log "Failed to find VC Tools path!"
            }
        }
    }
    # Package debug symbols on macos
    if ($Platform -eq "macos") {
        $BuiltArtifacts = Get-ChildItem $ArtifactsDir -File
        foreach ($Artifact in $BuiltArtifacts) {
            if (Test-Path $Artifact) {
                dsymutil $Artifact
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
