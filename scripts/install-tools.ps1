
if (Test-Path "$PSScriptRoot\win-installer-helper.psm1")
{
    Import-Module "$PSScriptRoot\win-installer-helper.psm1"
}
elseif (Test-Path "C:\win-installer-helper.psm1")
{
    Import-Module "C:\win-installer-helper.psm1"
}

$JomVersion = "1_1_3"
$NasmVersion = "2.15.05"
$ProgressPreference = 'SilentlyContinue'

Start-Setup

try {

    Write-Host "Installing jom"
    Get-File -Url "https://qt.mirror.constant.com/official_releases/jom/jom_$JomVersion.zip" -FileName "jom.zip"
    Expand-Archive -Path "C:\Downloads\jom.zip" -DestinationPath "C:\ExtraTools\jom" -Force
    Write-Host "Installed jom"

    Write-Host "Installing nasm"
    Get-File -Url "https://www.nasm.us/pub/nasm/releasebuilds/$NasmVersion/win64/nasm-$NasmVersion-win64.zip" -FileName "nasm.zip"
    Expand-Archive -Path "C:\Downloads\nasm.zip" -DestinationPath "C:\ExtraTools" -Force
    Write-Host "Installed nasm"

    Update-Path -PathNodes @("C:\ExtraTools\jom;C:\ExtraTools\nasm-$NasmVersion\;C:\Program Files\CMake\bin;$env:PERL;")

    Write-Host "Installing CMake"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Get-File -Url "https://github.com/Kitware/CMake/releases/download/v3.21.1/cmake-3.21.1-windows-x86_64.msi" -FileName "cmake.msi"
    Install-FromMSI -Path "C:\Downloads\cmake.msi"
    Write-Host "Installed CMake"

    Write-Host "Installing Pwsh"
    Get-File -Url "https://github.com/PowerShell/PowerShell/releases/download/v7.1.3/PowerShell-7.1.3-win-x64.msi" -FileName "powershell.msi"
    Install-FromMSI -Path "C:\Downloads\powershell.msi"
    Write-Host "Installed Pwsh"

} finally {
    Stop-Setup
}
