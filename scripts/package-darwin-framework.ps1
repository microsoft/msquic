<#

.SYNOPSIS
    This script assembles darwin binaries into a framework

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("macos", "ios")]
    [string]$Platform = "macos",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x64", "arm64", "universal")]
    [string]$Arch = "universal",

    [Parameter(Mandatory = $false)]
    [ValidateSet("openssl")]
    [string]$Tls = "openssl",

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

if (!$IsMacOS) {
    Write-Error "This script can only be ran on macOS"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Important directory paths.
$BaseArtifactsDir = Join-Path $RootDir "artifacts"

if ([string]::IsNullOrWhitespace($ExtraArtifactDir)) {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "bin" $Platform "$($Arch)_$($Config)_$($Tls)"
} else {
    $ArtifactsDir = Join-Path $BaseArtifactsDir "bin" $Platform "$($Arch)_$($Config)_$($Tls)_$($ExtraArtifactDir)"
}

$FrameworkDir = Join-Path $BaseArtifactsDir frameworks $Platform "$($Arch)_$($Config)_$($Tls)"  "msquic.framework"

if ((Test-Path $FrameworkDir)) {
    Remove-Item -Path "$FrameworkDir/*" -Recurse -Force
}

# Copy in headers
$FrameworkHeadersDir = Join-Path $FrameworkDir "Headers"

New-Item -Path $FrameworkHeadersDir -ItemType Directory -Force | Out-Null

$HeaderDir = Join-Path $RootDir "src/inc"

# Find Headers

$Headers = @(Join-Path $HeaderDir "msquic.h")
$Headers += Join-Path $HeaderDir  "msquic_posix.h"
$Headers += Join-Path $HeaderDir  "quic_sal_stub.h"

foreach ($Header in $Headers) {
    $FileName = Split-Path -Path $Header -Leaf
    $CopyToFolder = (Join-Path $FrameworkHeadersDir $FileName)
    Copy-Item -LiteralPath $Header -Destination $CopyToFolder -Force
}

# Copy in license
Copy-Item -Path (Join-Path $RootDir "LICENSE") -Destination $FrameworkDir
Copy-Item -Path (Join-Path $RootDir "THIRD-PARTY-NOTICES") -Destination $FrameworkDir

$InfoFile = Join-Path $FrameworkDir Info.plist

Copy-Item -LiteralPath (Join-Path $RootDir src distribution Info.plist) -Destination $InfoFile -Force

if ($Platform -eq "ios") {
    if ($Arch -eq "x64") {
        $PlistPlatform = "iPhoneSimulator"
    } else {
        $PlistPlatform = "iPhoneOS"
    }
} else {
    $PlistPlatform = "MacOSX"
}

(Get-Content $InfoFile) `
    -replace "InsertPlatformHere", "$PlistPlatform" |`
    Out-File $InfoFile

$DynamicFile = Join-Path $ArtifactsDir libmsquic.dylib
$StaticFile = Join-Path $ArtifactsDir libmsquic.a
$DestFile = Join-Path $FrameworkDir msquic

if (Test-Path $DynamicFile) {
    Copy-Item -Path $DynamicFile -Destination $DestFile -Force
    install_name_tool -id "@rpath/msquic.framework/msquic" $DestFile
    dsymutil $DestFile
} elseif (Test-Path $StaticFile) {
    Copy-Item -LiteralPath $StaticFile -Destination $DestFile -Force
} else {
    Write-Error "Failed to find binary"
}
