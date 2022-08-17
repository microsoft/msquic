
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

    Write-Host "Installing EWDK build environment"

    Get-File -Url "https://software-download.microsoft.com/download/pr/EWDK_co_release_22000_210604-1628.iso" -FileName "EWDK_co_release_22000_210604-1628.iso"
    C:\7-Zip\7z.exe x -y -oC:\ewdk C:\Downloads\EWDK_co_release_22000_210604-1628.iso
	del C:\Downloads\*.iso

    # Remove unnecessary items from ewdk to speed up image download
    Remove-Item -Path "C:\ewdk\Program Files\Microsoft Visual Studio\2019\BuildTools\VC\Tools\Llvm" -Recurse -Force

    # Get all folders in MSVC
    $Toolchains = (Get-ChildItem -Path "C:\ewdk\Program Files\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC" | Select-Object -ExpandProperty FullName)

    foreach ($TC in $Toolchains) {
        Remove-Item -Path (Join-Path $TC atlmfc) -Recurse -Force
        $LibFolders = Get-ChildItem -Path (Join-Path $TC lib) -Exclude "spectre"
        $LibFolders | Remove-Item -Force -Recurse

        Remove-Item -Path (Join-Path $TC "lib\spectre\onecore") -Recurse -Force
        $LibFolders = Get-ChildItem -Path (Join-Path $TC "lib\spectre") -Exclude "arm","arm64","x64","x86"
        $LibFolders | Remove-Item -Force -Recurse
    }


    Write-Output "Unzipped EWDK files to C:\ewdk."

} finally {
    Stop-Setup
}
