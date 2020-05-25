<#

.SYNOPSIS
This installs procdump in the build directory on the local machine.

.EXAMPLE
    install-procdump.ps1

#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Installation directory for procdump.
$ToolsDir = Join-Path $RootDir "build" "tools"
if (!(Test-Path $ToolsDir)) {
    New-Item -Path $ToolsDir -ItemType Directory -Force | Out-Null
}

# Install procdump on Windows if not already present.
if ($IsWindows -and !(Test-Path (Join-Path $ToolsDir "procdump64.exe"))) {

    Write-Host "[$(Get-Date)] Installing procdump..."

    # Create installation directory.
    New-Item -Path $ToolsDir -ItemType Directory -Force | Out-Null

    # Download the zip file.
    $ZipFile = Join-Path $ToolsDir "Procdump.zip"
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/Procdump.zip -OutFile $ZipFile

    # Extract the zip file.
    Expand-Archive -Path $ZipFile $ToolsDir

    # Delete the unused files.
    Remove-Item -Path $ZipFile
    Remove-Item -Path (Join-Path $ToolsDir "Eula.txt")
    Remove-Item -Path (Join-Path $ToolsDir "procdump.exe")

    Write-Host "[$(Get-Date)] procdump installed."
}
