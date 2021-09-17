

function FindKitTool {
    param (
        [string]$Arch = "x86",
        [Parameter(Mandatory = $true)]
        [string]$Tool
    )

    $KitBinRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (!(Test-Path $KitBinRoot)) {
        Write-Error "Windows Kit Binary Folder not Found"
        return ""
    }

    $FoundToolPath = $null
    $FoundToolVersion = "0"

    $Subfolders = Get-ChildItem -Path $KitBinRoot -Directory
    foreach ($Subfolder in $Subfolders) {
        $ToolPath = Join-Path $Subfolder "$Arch\$Tool"
        if (Test-Path $ToolPath) {
            $KitVersion = $Subfolder.Name

            if ($KitVersion -gt $FoundToolVersion) {
                $FoundToolVersion = $KitVersion
                $FoundToolPath = $ToolPath
            }
        }
    }

    if ($null -ne $FoundToolPath) {
        return $FoundToolPath
    }
    Write-Error "Failed to find tool"
    return $null
}

FindKitTool -Tool "signtool.exe"
