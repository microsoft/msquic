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
$ProcdumpDir = Join-Path $RootDir "bld" "windows" "procdump"

# Install procdump on Windows if not already present.
if ($IsWindows -and !(Test-Path $ProcdumpDir)) {

    Write-Host "[$(Get-Date)] Installing procdump..."

    # Create installation directory.
    New-Item -Path $ProcdumpDir -ItemType Directory -Force | Out-Null

    # Download the zip file.
    $ZipFile = $ProcdumpDir + ".zip"
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/Procdump.zip -OutFile $ZipFile

    # Extract the zip file.
    Expand-Archive -Path $ZipFile $ProcdumpDir

    # Delete the zip file.
    Remove-Item -Path $ZipFile
}
