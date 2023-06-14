<#

.SYNOPSIS
This signs and packages the drivers.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Tls
    Specifies the TLS library to use.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "openssl3")]
    [string]$Tls = ""
)

Set-StrictMode -Version 'Latest'
$ErrorActionPreference = 'Stop'

function Get-WindowsKitTool {
    param (
        [string]$Arch = "x86",
        [Parameter(Mandatory = $true)]
        [string]$Tool
    )

    $KitBinRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (!(Test-Path $KitBinRoot)) {
        Write-Error "Windows Kit Binary Folder not Found"
        return $null
    }


    $Subfolders = Get-ChildItem -Path $KitBinRoot -Directory | Sort-Object -Descending
    foreach ($Subfolder in $Subfolders) {
        $ToolPath = Join-Path $Subfolder.FullName "$Arch\$Tool"
        if (Test-Path $ToolPath) {
            return $ToolPath
        }
    }

    Write-Error "Failed to find tool"
    return $null
}

# Tool paths.
$SignToolPath = Get-WindowsKitTool -Tool "signtool.exe"
if (!(Test-Path $SignToolPath)) { Write-Error "$SignToolPath does not exist!" }

# Artifact paths.
$RootDir = (Split-Path $PSScriptRoot -Parent)
$ArtifactsDir = Join-Path $RootDir "artifacts\bin\winkernel\$($Arch)_$($Config)_$($Tls)"

# Signing certificate path.
$CertPath = Join-Path $RootDir "artifacts\corenet-ci-main\vm-setup\CoreNetSign.pfx"
if (!(Test-Path $CertPath)) { Write-Error "$CertPath does not exist!" }

# All the file paths.
$DriverFiles = @(
    (Join-Path $ArtifactsDir "msquic.sys"),
    (Join-Path $ArtifactsDir "msquicpriv.sys"),
    (Join-Path $ArtifactsDir "secnetperfdrv.sys"),
    (Join-Path $ArtifactsDir "secnetperfdrvpriv.sys"),
    (Join-Path $ArtifactsDir "msquictestpriv.sys")
)

# Sign the driver files.
foreach ($File in $DriverFiles) {
    if (!(Test-Path $File)) {
        Write-Host "Warning: $File does not exist! Skipping signing."
    } else {
        & $SignToolPath sign /f $CertPath -p "placeholder" /fd SHA256 $File
        if ($LastExitCode) { Write-Error "signtool.exe exit code: $LastExitCode" }
    }
}
