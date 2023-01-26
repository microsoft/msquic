
if (Test-Path "$PSScriptRoot\win-installer-helper.psm1")
{
    Import-Module "$PSScriptRoot\win-installer-helper.psm1"
}
elseif (Test-Path "C:\win-installer-helper.psm1")
{
    Import-Module "C:\win-installer-helper.psm1"
}

$ProgressPreference = 'SilentlyContinue'

Start-Setup

try {

    Write-Host "Installing additional visual studio workloads"

    $vsInstallerPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vs_installer.exe"

    $installerArgs = "modify --config `"C:\vsconfig.2019`" --installPath `"${env:VS2019}`" --quiet --norestart --nocache"
    Install-FromEXE -Path $vsInstallerPath -Arguments $installerArgs

    Write-Output "Installed additional visual studio workloads"

} catch {
    Write-Host "Error during workloads installation"
    dir $Env:TEMP -Filter *.log | where Length -gt 0 | Get-Content
    dir $Env:TEMP -Filter *.txt | where Length -gt 0 | Get-Content
    $_.Exception | Format-List -Force
    exit 1
} finally {
    Stop-Setup
}
