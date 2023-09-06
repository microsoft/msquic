
# Usage: ./generate-docfx-yml.ps1 <directoryPath>
#
# Recursively iterates directoryPath and creates a toc.yml in each subdirectory,
# generating a table of contents for each markdown file. This is useful for docfx
# as docfx requires a manifest for just in time static site compilation.
#

param (
    [string]$directoryPath
)

# Check if the powershell-yaml module is installed, and if not, install it
$module = Get-Module -Name powershell-yaml -ListAvailable
if ($module -eq $null) {
    Write-Host "The 'powershell-yaml' module is not installed. Installing it..."
    Install-Module -Name powershell-yaml -Scope CurrentUser -Force
}

# Import the powershell-yaml module
Import-Module powershell-yaml

function CreateTocFile($directory) {
    $tocPath = Join-Path $directory "toc.yml"
    $markdownFiles = Get-ChildItem -Path $directory -Filter "*.md" -File

    $tocContent = @()
    foreach ($file in $markdownFiles) {
        $name = $file.BaseName
        $href = $file.Name
        $tocItem = @{
            name = $name
            href = $href
        }
        $tocContent += $tocItem
    }

    if ($tocContent.Count -gt 0) {
        $tocContent | ConvertTo-Yaml | Out-String | Out-File -FilePath $tocPath -Force
        Write-Host "Created $tocPath"
    } else {
        Write-Host "No markdown files found in $directory. Skipping toc.yml creation."
    }
}

function ProcessDirectories($directory) {
    # Process the current directory
    CreateTocFile $directory

    # Recursively process subdirectories
    $subdirectories = Get-ChildItem -Path $directory -Directory
    foreach ($subdir in $subdirectories) {
        ProcessDirectories $subdir.FullName
    }
}

if (Test-Path -Path $directoryPath -PathType Container) {
    ProcessDirectories $directoryPath
} else {
    Write-Host "Invalid directory path: $directoryPath" -ForegroundColor Red
}
