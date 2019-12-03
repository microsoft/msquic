<#

.SYNOPSIS
Gets procdump from the web if it doesn't already exist.

#>

if ((Test-Path .\bld\procdump) -eq $false) {
    # Download the zip file.
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/Procdump.zip -OutFile bld\procdump.zip
    # Extract the zip file.
    Expand-Archive -Path bld\procdump.zip .\bld\procdump
    # Delete the zip file.
    Remove-Item -Path bld\procdump.zip
}